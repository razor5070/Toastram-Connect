use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};
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
    if args.len() != 3 || !(args[0] == "preflight" || args[0] == "pair" || args[0] == "pair-dialog")
    {
        return Err("Usage: toastlink preflight|pair CONNECTION_FILE OPERATOR_TRUST_JSON".into());
    }
    let file = ConnectionFile::from_path(Path::new(&args[1])).map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    File::open(&args[2])
        .and_then(|f| f.take(16385).read_to_end(&mut raw))
        .map_err(|_| "Cannot read operator trust record")?;
    if raw.len() > 16384 {
        return Err("Operator record exceeds size limit".into());
    }
    let trust: Trust = serde_json::from_slice(&raw).map_err(|_| "Invalid operator trust record")?;
    let eligible = Pairing::new(&file, &trust)
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
            let locator = eligible
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
