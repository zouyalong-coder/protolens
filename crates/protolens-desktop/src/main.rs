use protolens_capture::CaptureInterface;
use protolens_controller::{CaptureRunConfig, capture_interfaces, replay_pcap_file, run_capture};
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use tauri::{AppHandle, Emitter, State};
use tauri_plugin_dialog::DialogExt;

#[derive(Default)]
struct CaptureState {
    running: Mutex<Option<Arc<AtomicBool>>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StartCaptureRequest {
    interface: String,
    filter: String,
    count: Option<usize>,
    payload_limit: usize,
    pcap_output_path: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoadCaptureRequest {
    path: String,
    payload_limit: usize,
}

#[tauri::command]
fn list_interfaces() -> Result<Vec<CaptureInterface>, String> {
    capture_interfaces().map_err(|error| error.to_string())
}

#[tauri::command]
fn start_capture(
    app: AppHandle,
    state: State<'_, CaptureState>,
    request: StartCaptureRequest,
) -> Result<(), String> {
    if request.interface.trim().is_empty() {
        return Err("capture interface is required".to_owned());
    }

    let mut running_slot = state
        .running
        .lock()
        .map_err(|_| "capture state lock poisoned".to_owned())?;

    if running_slot
        .as_ref()
        .is_some_and(|running| running.load(Ordering::SeqCst))
    {
        return Err("capture is already running".to_owned());
    }

    let running = Arc::new(AtomicBool::new(true));
    *running_slot = Some(Arc::clone(&running));
    drop(running_slot);

    let config = CaptureRunConfig::pcap(
        request.interface,
        request.filter,
        request.count,
        request.payload_limit,
        request
            .pcap_output_path
            .and_then(|path| (!path.trim().is_empty()).then(|| PathBuf::from(path))),
    );
    let thread_running = Arc::clone(&running);

    std::thread::spawn(move || {
        let result = run_capture(
            config,
            |event| {
                app.emit("capture-event", event)
                    .map_err(|error| protolens_core_error(error.to_string()))?;
                Ok(())
            },
            || thread_running.load(Ordering::SeqCst),
        );

        if let Err(error) = result {
            let _ = app.emit("capture-error", error.to_string());
        }

        thread_running.store(false, Ordering::SeqCst);
        let _ = app.emit("capture-stopped", ());
    });

    Ok(())
}

#[tauri::command]
fn stop_capture(state: State<'_, CaptureState>) -> Result<(), String> {
    let running_slot = state
        .running
        .lock()
        .map_err(|_| "capture state lock poisoned".to_owned())?;

    if let Some(running) = running_slot.as_ref() {
        running.store(false, Ordering::SeqCst);
    }

    Ok(())
}

#[tauri::command]
async fn select_save_pcap_path(app: AppHandle) -> Result<Option<String>, String> {
    dialog_path_to_string(
        app.dialog()
            .file()
            .add_filter("Packet Capture", &["pcap"])
            .set_file_name("protolens.pcap")
            .set_title("Save capture as PCAP")
            .blocking_save_file(),
    )
}

#[tauri::command]
async fn select_load_pcap_path(app: AppHandle) -> Result<Option<String>, String> {
    dialog_path_to_string(
        app.dialog()
            .file()
            .add_filter("Packet Capture", &["pcap", "pcapng"])
            .set_title("Open capture file")
            .blocking_pick_file(),
    )
}

#[tauri::command]
fn load_capture_file(app: AppHandle, request: LoadCaptureRequest) -> Result<usize, String> {
    if request.path.trim().is_empty() {
        return Err("pcap file path is required".to_owned());
    }

    replay_pcap_file(
        PathBuf::from(request.path),
        request.payload_limit,
        |event| {
            app.emit("capture-event", event)
                .map_err(|error| protolens_core_error(error.to_string()))?;
            Ok(())
        },
    )
    .map_err(|error| error.to_string())
}

fn dialog_path_to_string(
    path: Option<tauri_plugin_dialog::FilePath>,
) -> Result<Option<String>, String> {
    path.map(|path| {
        path.into_path()
            .map(|path| path.display().to_string())
            .map_err(|error| error.to_string())
    })
    .transpose()
}

fn protolens_core_error(message: String) -> protolens_core::Error {
    protolens_core::Error::Sink {
        sink: "tauri-event".to_owned(),
        message,
    }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(CaptureState::default())
        .invoke_handler(tauri::generate_handler![
            list_interfaces,
            start_capture,
            stop_capture,
            select_save_pcap_path,
            select_load_pcap_path,
            load_capture_file
        ])
        .run(tauri::generate_context!())
        .expect("failed to run ProtoLens desktop app");
}
