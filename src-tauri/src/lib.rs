// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Mutex;
use tauri::Manager;

/// Global state holding the sidecar child process handle.
struct SidecarState {
    child: Mutex<Option<std::process::Child>>,
}

/// Tauri command: read the sidecar port from the temp file.
#[tauri::command]
fn get_sidecar_port() -> Result<u16, String> {
    let port_file = std::env::temp_dir().join("agentarmor_sidecar.port");

    // Retry a few times — the sidecar may still be starting up
    for _ in 0..20 {
        if let Ok(contents) = std::fs::read_to_string(&port_file) {
            if let Ok(port) = contents.trim().parse::<u16>() {
                return Ok(port);
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }

    Err(format!(
        "Could not read sidecar port from {}",
        port_file.display()
    ))
}

/// Spawn the Python FastAPI sidecar process.
fn spawn_sidecar() -> Result<std::process::Child, String> {
    // Resolve the sidecar script path relative to the executable
    let exe_dir = std::env::current_exe()
        .map(|p| p.parent().unwrap_or(std::path::Path::new(".")).to_path_buf())
        .unwrap_or_else(|_| std::path::PathBuf::from("."));

    // In development, the sidecar lives at <project>/sidecar/main.py
    // In production, it's bundled next to the executable
    let sidecar_script = if cfg!(debug_assertions) {
        // Dev mode: look relative to the Cargo project root
        let project_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap_or(std::path::Path::new("."));
        project_root.join("sidecar").join("main.py")
    } else {
        exe_dir.join("sidecar").join("main.py")
    };

    std::process::Command::new("python")
        .arg(&sidecar_script)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn sidecar: {e}"))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .setup(|app| {
            // Spawn the Python sidecar on app start
            match spawn_sidecar() {
                Ok(child) => {
                    app.manage(SidecarState {
                        child: Mutex::new(Some(child)),
                    });
                    println!("[AgentArmor Studio] Sidecar started");
                }
                Err(e) => {
                    eprintln!("[AgentArmor Studio] Warning: {e}");
                    app.manage(SidecarState {
                        child: Mutex::new(None),
                    });
                }
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // Kill the sidecar when the main window is destroyed
            if let tauri::WindowEvent::Destroyed = event {
                if let Some(state) = window.try_state::<SidecarState>() {
                    if let Ok(mut guard) = state.child.lock() {
                        if let Some(ref mut child) = *guard {
                            let _ = child.kill();
                            println!("[AgentArmor Studio] Sidecar killed");
                        }
                    }
                }
                // Clean up the port file
                let port_file = std::env::temp_dir().join("agentarmor_sidecar.port");
                let _ = std::fs::remove_file(port_file);
            }
        })
        .invoke_handler(tauri::generate_handler![get_sidecar_port])
        .run(tauri::generate_context!())
        .expect("error while running AgentArmor Studio");
}
