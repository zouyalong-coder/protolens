use protolens_capture::CaptureInterface;
use protolens_controller::{CaptureRunConfig, capture_interfaces, run_capture};
use serde::Deserialize;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use tauri::{AppHandle, Emitter, State};

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

fn protolens_core_error(message: String) -> protolens_core::Error {
    protolens_core::Error::Sink {
        sink: "tauri-event".to_owned(),
        message,
    }
}

fn main() {
    tauri::Builder::default()
        .manage(CaptureState::default())
        .invoke_handler(tauri::generate_handler![
            list_interfaces,
            start_capture,
            stop_capture
        ])
        .run(tauri::generate_context!())
        .expect("failed to run ProtoLens desktop app");
}
