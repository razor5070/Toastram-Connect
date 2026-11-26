#[cfg(windows)]
use std::io;
use std::{fs::File, io::Read, path::Path};
use toastlink_core::{
    pairing::{Pairing, Trust},
    ConnectionFile,
};

#[cfg(windows)]
fn confirm_windows(origin: &str) -> bool {
    #[link(name = "user32")]
    extern "system" {
        fn MessageBoxW(
            hwnd: *mut std::ffi::c_void,
            text: *const u16,
            title: *const u16,
            flags: u32,
        ) -> i32;
    }
    let message: Vec<u16> = format!("Pair with {origin}? This consumes the enrollment file once and stores a client credential in Windows Credential Manager.").encode_utf16().chain(Some(0)).collect();
    let title: Vec<u16> = "ToastRAM Connect".encode_utf16().chain(Some(0)).collect();
    // Both strings are NUL terminated and live until the dialog returns. Default is No.
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            message.as_ptr(),
            title.as_ptr(),
            0x4 | 0x100 | 0x10000,
        ) == 6
    }
}

fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    #[cfg(windows)]
    if args.len() == 4 && args[0] == "resume" {
        let read = |path: &std::ffi::OsStr, max: u64| -> Result<Vec<u8>, String> {
            let mut bytes = Vec::new();
            File::open(path)
                .and_then(|f| f.take(max + 1).read_to_end(&mut bytes))
                .map_err(|_| "Cannot read pairing files")?;
            if bytes.len() as u64 > max {
                return Err("Input too large".into());
            }
            Ok(bytes)
        };
        let bytes = zeroize::Zeroizing::new(read(&args[1], 65536)?);
        let trust =
            serde_json::from_slice(&read(&args[2], 16384)?).map_err(|_| "Invalid trust record")?;
        return toastlink_core::pairing::resume_windows(
            &bytes,
            trust,
            args[3].to_str().ok_or("Invalid client ID")?,
        )
        .map_err(|e| format!("Session recovery: {e:?}"));
    }
    if (args.len() == 2 || (args.len() == 4 && args[2] == "--output")) && args[0] == "inspect" {
        let file = ConnectionFile::from_path(Path::new(&args[1])).map_err(|e| e.to_string())?;
        let preview: serde_json::Value =
            serde_json::from_str(&file.public_metadata_json()).map_err(|_| "Invalid metadata")?;
        #[cfg(windows)]
        let preview = {
            let mut preview = preview;
            preview["previous_binding_changed"] = serde_json::Value::Bool(
                toastlink_core::pairing::previous_binding_changed(&file)
                    .map_err(|_| "Cannot inspect existing session bindings")?,
            );
            preview
        };
        let metadata = preview.to_string();
        if args.len() == 4 {
            use std::io::Write;
            let mut output = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&args[3])
                .map_err(|_| "Cannot create identity preview")?;
            output
                .write_all(metadata.as_bytes())
                .map_err(|_| "Cannot write identity preview")?;
        } else {
            println!("{metadata}");
        }
        return Ok(());
    }
    let inline_trust = args.len() == 4 && args[2] == "--verified-tuple";
    if !(inline_trust || args.len() == 3)
        || !(args[0] == "preflight" || args[0] == "pair" || args[0] == "pair-dialog")
    {
        return Err("Usage: toastlink inspect FILE or toastlink preflight|pair|pair-dialog FILE TRUST_RECORD".into());
    }
    let file = ConnectionFile::from_path(Path::new(&args[1])).map_err(|e| e.to_string())?;
    let raw = if inline_trust {
        args[3]
            .to_str()
            .ok_or("Invalid trusted tuple")?
            .as_bytes()
            .to_vec()
    } else {
        let mut raw = Vec::new();
        File::open(&args[2])
            .and_then(|f| f.take(16385).read_to_end(&mut raw))
            .map_err(|_| "Cannot read operator trust record")?;
        raw
    };
    if raw.len() > 16384 {
        return Err("Operator record exceeds size limit".into());
    }
    let trust: Trust = serde_json::from_slice(&raw).map_err(|_| "Invalid operator trust record")?;
    #[cfg(windows)]
    if toastlink_core::pairing::previous_binding_changed(&file)
        .map_err(|_| "Cannot verify existing session bindings")?
    {
        return Err("Server identity changed. Enrollment blocked.".into());
    }
    let _eligible = Pairing::new(&file, &trust)
        .and_then(Pairing::preflight)
        .map_err(|e| format!("Preflight: {e:?}"))?;
    println!("Eligible at {}", file.server_url());
    if args[0] != "preflight" {
        #[cfg(windows)]
        {
            let consent = if args[0] == "pair-dialog" {
                confirm_windows(file.server_url())
            } else {
                println!("Type PAIR to redeem once and store the credential in Windows Credential Manager.");
                let mut answer = String::new();
                io::stdin()
                    .read_line(&mut answer)
                    .map_err(|_| "Cannot read consent")?;
                answer.trim() == "PAIR"
            };
            if !consent {
                return Err("Pairing cancelled".into());
            }
            let locator = _eligible
                .redeem_windows()
                .map_err(|e| format!("Redemption: {e:?}"))?;
            println!("Credential stored: {locator}");
        }
        #[cfg(not(windows))]
        return Err("Protected credential storage requires Windows in this build".into());
    }
    Ok(())
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            match e.as_str() {
                "Redemption: RedemptionUncertain" => 3.into(),
                "Pairing cancelled" => 2.into(),
                _ => std::process::ExitCode::FAILURE,
            }
        }
    }
}
