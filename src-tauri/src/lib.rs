// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Mutex;
use tauri::Manager;

/// Global state holding the sidecar child process handle and any launch errors.
struct SidecarState {
    child: Mutex<Option<std::process::Child>>,
    launch_error: Mutex<Option<String>>,
}

/// Tauri command: read the sidecar port from the temp file.
#[tauri::command]
fn get_sidecar_port() -> Result<u16, String> {
    let port_file = std::env::temp_dir().join("agentarmor_sidecar.port");

    // Retry a few times — the sidecar may still be starting up
    for _ in 0..40 {
        if let Ok(contents) = std::fs::read_to_string(&port_file) {
            if let Ok(port) = contents.trim().parse::<u16>() {
                return Ok(port);
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }

    Err(format!(
        "Could not read sidecar port from {}. The sidecar may have failed to start.",
        port_file.display()
    ))
}

/// Tauri command: return sidecar diagnostic info for the frontend.
#[tauri::command]
fn get_sidecar_status(state: tauri::State<SidecarState>) -> Result<String, String> {
    // Check if there was a launch error
    if let Ok(err) = state.launch_error.lock() {
        if let Some(ref e) = *err {
            return Err(format!("Sidecar failed to start: {e}"));
        }
    }

    // Check if the child process is still alive
    if let Ok(mut guard) = state.child.lock() {
        if let Some(ref mut child) = *guard {
            match child.try_wait() {
                Ok(Some(exit_status)) => {
                    return Err(format!(
                        "Sidecar process exited unexpectedly with status: {exit_status}"
                    ));
                }
                Ok(None) => {
                    // Still running — good
                    return Ok("Sidecar is running".to_string());
                }
                Err(e) => {
                    return Err(format!("Could not check sidecar status: {e}"));
                }
            }
        }
    }

    Err("Sidecar was never started".to_string())
}

/// Spawn the sidecar process.
///
/// - **Dev mode**: runs `python ../sidecar/main.py`
/// - **Release mode**: runs the bundled `agentarmor-sidecar.exe` next to the main executable
fn spawn_sidecar() -> Result<std::process::Child, String> {
    let exe_dir = std::env::current_exe()
        .map(|p| p.parent().unwrap_or(std::path::Path::new(".")).to_path_buf())
        .unwrap_or_else(|_| std::path::PathBuf::from("."));

    if cfg!(debug_assertions) {
        // ── Dev mode ──────────────────────────────────────────────────────
        let project_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap_or(std::path::Path::new("."));
        let sidecar_script = project_root.join("sidecar").join("main.py");

        eprintln!(
            "[AgentArmor Studio] DEV: spawning python {}",
            sidecar_script.display()
        );

        std::process::Command::new("python")
            .arg(&sidecar_script)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to spawn sidecar (dev): {e}"))
    } else {
        // ── Release mode ──────────────────────────────────────────────────
        // Search for the sidecar binary in all likely locations.
        // Tauri resources can end up next to exe or in a binaries/ subdir,
        // and the file may be named plain or with the target triple suffix.
        let candidates = [
            exe_dir.join("agentarmor-sidecar.exe"),
            exe_dir.join("agentarmor-sidecar-x86_64-pc-windows-msvc.exe"),
            exe_dir.join("binaries").join("agentarmor-sidecar.exe"),
            exe_dir.join("binaries").join("agentarmor-sidecar-x86_64-pc-windows-msvc.exe"),
        ];

        let sidecar_path = candidates.iter().find(|p| p.exists());

        let sidecar_path = match sidecar_path {
            Some(p) => p.clone(),
            None => {
                let searched: String = candidates
                    .iter()
                    .map(|p| format!("  - {}", p.display()))
                    .collect::<Vec<_>>()
                    .join("\n");
                return Err(format!("Sidecar binary not found. Searched:\n{searched}"));
            }
        };

        eprintln!(
            "[AgentArmor Studio] RELEASE: spawning {}",
            sidecar_path.display()
        );

        std::process::Command::new(&sidecar_path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| {
                format!(
                    "Failed to spawn sidecar at {}: {e}",
                    sidecar_path.display()
                )
            })
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_process::init())
        .setup(|app| {
            // Spawn the Python sidecar on app start
            match spawn_sidecar() {
                Ok(child) => {
                    app.manage(SidecarState {
                        child: Mutex::new(Some(child)),
                        launch_error: Mutex::new(None),
                    });
                    eprintln!("[AgentArmor Studio] Sidecar started successfully");
                }
                Err(e) => {
                    eprintln!("[AgentArmor Studio] ERROR: {e}");
                    app.manage(SidecarState {
                        child: Mutex::new(None),
                        launch_error: Mutex::new(Some(e)),
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
                            eprintln!("[AgentArmor Studio] Sidecar killed");
                        }
                    }
                }
                // Clean up the port file
                let port_file = std::env::temp_dir().join("agentarmor_sidecar.port");
                let _ = std::fs::remove_file(port_file);
            }
        })
        .invoke_handler(tauri::generate_handler![get_sidecar_port, get_sidecar_status])
        .run(tauri::generate_context!())
        .expect("error while running AgentArmor Studio");
}
