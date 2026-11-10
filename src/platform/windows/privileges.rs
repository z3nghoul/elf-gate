use crate::platform::{InvokingUser, PlatformError, Privileges};
use std::path::Path;
use windows::core::{w, HSTRING};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

pub struct Elevation;

/// Quotes one command-line argument for `ShellExecuteW` (spaces and quotes).
fn quote(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
        return arg.to_string();
    }
    format!("\"{}\"", arg.replace('"', "\\\""))
}

impl Privileges for Elevation {
    fn is_elevated(&self) -> bool {
        // SAFETY: the token handle is opened for query only, filled by GetTokenInformation
        // into a correctly sized TOKEN_ELEVATION, and closed before returning.
        unsafe {
            let mut token = HANDLE::default();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
                return false;
            }
            let mut elevation = TOKEN_ELEVATION::default();
            let mut returned = 0u32;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut _),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut returned,
            )
            .is_ok();
            let _ = CloseHandle(token);
            ok && elevation.TokenIsElevated != 0
        }
    }

    fn invoking_user(&self) -> Option<InvokingUser> {
        None
    }

    fn chown_to_invoking_user(&self, _path: &Path) -> Result<(), PlatformError> {
        Ok(())
    }

    fn relaunch_elevated(&self, args: &[String]) -> Result<(), PlatformError> {
        let exe = std::env::current_exe()
            .map_err(|e| PlatformError::Failed(format!("current_exe: {e}")))?;
        let params = args.iter().map(|a| quote(a)).collect::<Vec<_>>().join(" ");
        // SAFETY: all strings are valid HSTRINGs that outlive the call; "runas" asks for UAC.
        let result = unsafe {
            ShellExecuteW(
                None,
                w!("runas"),
                &HSTRING::from(exe.as_os_str()),
                &HSTRING::from(params),
                None,
                SW_SHOWNORMAL,
            )
        };
        // ShellExecuteW returns a value greater than 32 on success.
        if result.0 as isize > 32 {
            Ok(())
        } else {
            Err(PlatformError::Failed(
                "запуск с правами администратора отменён или не удался".into(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::quote;

    #[test]
    fn quotes_only_when_needed() {
        assert_eq!(quote("--tun"), "--tun");
        assert_eq!(quote("a b"), "\"a b\"");
        assert_eq!(quote("say \"hi\""), "\"say \\\"hi\\\"\"");
    }
}
