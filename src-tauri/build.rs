//! Build script for AgentArmor Studio.
//!
//! Runs PyInstaller to package the Python sidecar before the Tauri build.
//! Only re-runs PyInstaller if source files have changed (mtime check).

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

/// Return the most recent modification time across all files in `dir`.
fn newest_mtime(dir: &Path) -> Option<SystemTime> {
    let mut newest: Option<SystemTime> = None;

    if !dir.exists() {
        return None;
    }

    let walker = fs::read_dir(dir).ok()?;
    for entry in walker.flatten() {
        let path = entry.path();
        if path.is_file() {
            if let Ok(meta) = fs::metadata(&path) {
                if let Ok(mtime) = meta.modified() {
                    newest = Some(match newest {
                        Some(prev) if mtime > prev => mtime,
                        Some(prev) => prev,
                        None => mtime,
                    });
                }
            }
        }
    }

    newest
}

fn main() {
    // ── Resolve paths ──────────────────────────────────────────────────────
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let sidecar_dir = manifest_dir.parent().unwrap().join("sidecar");
    let sidecar_main = sidecar_dir.join("main.py");
    let binaries_dir = manifest_dir.join("binaries");

    // Tauri sidecar naming convention: name-<target triple>.exe
    let target_triple = env::var("TARGET").unwrap_or_else(|_| {
        "x86_64-pc-windows-msvc".to_string()
    });
    let sidecar_binary = binaries_dir.join(format!(
        "agentarmor-sidecar-{}.exe",
        target_triple
    ));

    // ── Tell Cargo to re-run if sidecar source changes ─────────────────────
    println!("cargo:rerun-if-changed={}", sidecar_dir.display());
    println!("cargo:rerun-if-changed={}", sidecar_main.display());

    // ── Check if we need to rebuild ────────────────────────────────────────
    // CI pre-builds the sidecar and stages the binary, so skip PyInstaller.
    if env::var("SKIP_PYINSTALLER").is_ok() || env::var("CI").is_ok() {
        if sidecar_binary.exists() {
            println!("cargo:warning=CI mode: sidecar binary already staged, skipping PyInstaller.");
            tauri_build::build();
            return;
        } else {
            println!("cargo:warning=CI mode but sidecar binary not found at: {}", sidecar_binary.display());
        }
    }

    // ── Dev profile: skip PyInstaller entirely ────────────────────────────
    // In debug builds, lib.rs spawns `python ../sidecar/main.py` directly
    // via the user's interpreter — the bundled .exe is never used. Running
    // PyInstaller on every `cargo run` is wasted work (and fails if the
    // user doesn't happen to have pyinstaller installed).
    //
    // Tauri's bundle.resources = ["binaries/*"] requires the glob to match
    // at least one file, even in dev. Drop a placeholder so dev builds
    // don't blow up with "didn't match any files".
    if env::var("PROFILE").as_deref() == Ok("debug") {
        println!("cargo:warning=Dev (debug) profile: skipping PyInstaller. Sidecar will run via `python ../sidecar/main.py`.");
        fs::create_dir_all(&binaries_dir).expect("Failed to create binaries directory");
        let placeholder = binaries_dir.join(".dev-placeholder");
        if !placeholder.exists() {
            fs::write(&placeholder, b"Dev placeholder so Tauri's binaries/* glob always matches.\nReplaced by the real sidecar .exe in release builds.\n")
                .expect("Failed to write dev placeholder");
        }
        tauri_build::build();
        return;
    }

    let source_mtime = newest_mtime(&sidecar_dir);
    let binary_mtime = sidecar_binary
        .exists()
        .then(|| {
            fs::metadata(&sidecar_binary)
                .ok()
                .and_then(|m| m.modified().ok())
        })
        .flatten();

    let needs_rebuild = match (source_mtime, binary_mtime) {
        (Some(src), Some(bin)) => src > bin,
        (Some(_), None) => true,  // binary doesn't exist yet
        _ => true,                // can't determine, rebuild to be safe
    };

    if !needs_rebuild {
        println!("cargo:warning=Sidecar binary is up-to-date, skipping PyInstaller.");
        tauri_build::build();
        return;
    }

    // ── Ensure output directory exists ─────────────────────────────────────
    fs::create_dir_all(&binaries_dir).expect("Failed to create binaries directory");

    // ── Run PyInstaller ────────────────────────────────────────────────────
    println!("cargo:warning=Building sidecar with PyInstaller...");

    let spec_file = sidecar_dir.join("agentarmor_sidecar.spec");
    let dist_dir = sidecar_dir.join("dist");

    let status = Command::new("pyinstaller")
        .arg("--noconfirm")
        .arg("--distpath")
        .arg(dist_dir.to_str().unwrap())
        .arg(spec_file.to_str().unwrap())
        .current_dir(&sidecar_dir)
        .status()
        .expect("Failed to execute PyInstaller. Is it installed? Run: uv pip install pyinstaller (or set SKIP_PYINSTALLER=1 if staging the binary externally)");

    if !status.success() {
        panic!("PyInstaller failed with exit code: {:?}", status.code());
    }

    // ── Copy built binary to Tauri binaries dir ────────────────────────────
    let built_exe = dist_dir.join("agentarmor-sidecar.exe");
    if !built_exe.exists() {
        panic!(
            "PyInstaller output not found at: {}",
            built_exe.display()
        );
    }

    fs::copy(&built_exe, &sidecar_binary).expect("Failed to copy sidecar binary");
    println!(
        "cargo:warning=Sidecar binary copied to: {}",
        sidecar_binary.display()
    );

    // ── Run regular Tauri build steps ──────────────────────────────────────
    tauri_build::build();
}
