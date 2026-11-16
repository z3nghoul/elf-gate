//! The clipboard through PowerShell (`Get-Clipboard` / `Set-Clipboard`), text in UTF-8.

use crate::platform::{run_clipboard_tool, Clipboard, PlatformError, ToolRun};
use std::os::windows::process::CommandExt;
use std::process::Command;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub struct Clip;

fn powershell(script: &str) -> Command {
    let mut cmd = Command::new("powershell");
    cmd.args(["-NoProfile", "-NonInteractive", "-Command", script])
        .creation_flags(CREATE_NO_WINDOW);
    cmd
}

impl Clipboard for Clip {
    fn read(&self) -> Result<String, PlatformError> {
        let cmd = powershell(
            "[Console]::OutputEncoding=[Text.Encoding]::UTF8; $t=Get-Clipboard -Raw; if ($t) { [Console]::Out.Write($t) }",
        );
        match run_clipboard_tool(cmd, None, true) {
            Ok(ToolRun::Done(out)) => Ok(String::from_utf8_lossy(&out)
                .trim_start_matches('\u{feff}')
                .to_string()),
            Ok(ToolRun::Failed) => Ok(String::new()),
            Err(e) => Err(PlatformError::Failed(format!("powershell: {e}"))),
        }
    }

    fn write(&self, text: &str) -> Result<(), PlatformError> {
        let cmd = powershell(
            "[Console]::InputEncoding=[Text.Encoding]::UTF8; Set-Clipboard -Value ([Console]::In.ReadToEnd())",
        );
        match run_clipboard_tool(cmd, Some(text.as_bytes()), false) {
            Ok(ToolRun::Done(_)) => Ok(()),
            Ok(ToolRun::Failed) => Err(PlatformError::Failed("Set-Clipboard failed".into())),
            Err(e) => Err(PlatformError::Failed(format!("powershell: {e}"))),
        }
    }
}
