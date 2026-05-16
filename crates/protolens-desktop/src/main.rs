use protolens_capture::CaptureInterface;
use protolens_controller::{CaptureRunConfig, capture_interfaces, replay_pcap_file, run_capture};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::process::Command;
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DiagnoseTargetRequest {
    target: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TargetDiagnosis {
    target: String,
    host: String,
    port: u16,
    resolved_ips: Vec<String>,
    selected_ip: Option<String>,
    recommended_interface: Option<String>,
    bpf_filter: Option<String>,
    fake_ip: bool,
    notes: Vec<String>,
}

#[tauri::command]
fn list_interfaces() -> Result<Vec<CaptureInterface>, String> {
    capture_interfaces().map_err(|error| error.to_string())
}

#[tauri::command]
fn diagnose_target(request: DiagnoseTargetRequest) -> Result<TargetDiagnosis, String> {
    let target = request.target.trim();
    if target.is_empty() {
        return Err("target is required".to_owned());
    }

    let (host, port) = parse_target(target)?;
    let mut notes = Vec::new();
    let resolved_ips = resolve_target_ips(&host, port, &mut notes);
    let selected_ip = resolved_ips.first().copied();
    let route_interface = selected_ip.and_then(route_interface_for_ip);
    let fake_ip = selected_ip.is_some_and(is_fake_ip);

    if fake_ip {
        notes.push("Target resolved to a 198.18.0.0/15 proxy fake IP; capture the tunnel interface, not Wi-Fi.".to_owned());
    }

    if let Some(interface) = &route_interface {
        notes.push(format!(
            "System route for the selected IP uses {interface}."
        ));
    } else if selected_ip.is_some() {
        notes.push("No route interface could be detected for the selected IP.".to_owned());
    }

    let selected_ip_text = selected_ip.map(|ip| ip.to_string());
    Ok(TargetDiagnosis {
        target: target.to_owned(),
        host,
        port,
        resolved_ips: resolved_ips.iter().map(ToString::to_string).collect(),
        selected_ip: selected_ip_text.clone(),
        recommended_interface: route_interface,
        bpf_filter: selected_ip_text.map(|ip| format!("host {ip} and port {port}")),
        fake_ip,
        notes,
    })
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

fn parse_target(target: &str) -> Result<(String, u16), String> {
    let trimmed = target.trim();
    let without_scheme = trimmed
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(trimmed);
    let authority = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(without_scheme)
        .trim();

    if authority.is_empty() {
        return Err("target host is required".to_owned());
    }

    if let Some(rest) = authority.strip_prefix('[') {
        let (host, suffix) = rest
            .split_once(']')
            .ok_or_else(|| "invalid IPv6 target".to_owned())?;
        let port = suffix
            .strip_prefix(':')
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| default_port(trimmed));
        return Ok((host.to_owned(), port));
    }

    let colon_count = authority.matches(':').count();
    if colon_count == 1 {
        let (host, port_text) = authority.rsplit_once(':').unwrap_or((authority, ""));
        if let Ok(port) = port_text.parse::<u16>() {
            return Ok((host.to_owned(), port));
        }
    }

    Ok((authority.to_owned(), default_port(trimmed)))
}

fn default_port(target: &str) -> u16 {
    if target.starts_with("http://") {
        80
    } else {
        443
    }
}

fn resolve_target_ips(host: &str, port: u16, notes: &mut Vec<String>) -> Vec<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return vec![ip];
    }

    match (host, port).to_socket_addrs() {
        Ok(addresses) => {
            let mut ips = Vec::new();
            for address in addresses {
                if !ips.contains(&address.ip()) {
                    ips.push(address.ip());
                }
            }
            ips
        }
        Err(error) => {
            notes.push(format!("DNS resolution failed: {error}"));
            Vec::new()
        }
    }
}

fn is_fake_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            octets[0] == 198 && (octets[1] == 18 || octets[1] == 19)
        }
        IpAddr::V6(_) => false,
    }
}

#[cfg(target_os = "macos")]
fn route_interface_for_ip(ip: IpAddr) -> Option<String> {
    let output = Command::new("route")
        .args(["-n", "get", &ip.to_string()])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout.lines().find_map(|line| {
        let line = line.trim();
        line.strip_prefix("interface:")
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    })
}

#[cfg(not(target_os = "macos"))]
fn route_interface_for_ip(_ip: IpAddr) -> Option<String> {
    None
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(CaptureState::default())
        .invoke_handler(tauri::generate_handler![
            list_interfaces,
            diagnose_target,
            start_capture,
            stop_capture,
            select_save_pcap_path,
            select_load_pcap_path,
            load_capture_file
        ])
        .run(tauri::generate_context!())
        .expect("failed to run ProtoLens desktop app");
}
