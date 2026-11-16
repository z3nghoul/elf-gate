//! The clipboard through the tools of the desktop: `wl-paste`/`wl-copy` (Wayland), `xclip` or
//! `xsel` (X11). There is no library: a clipboard needs the session's event loop, a tool has it.

use crate::platform::{run_clipboard_tool, Clipboard, PlatformError, ToolRun};
use std::process::Command;

pub struct Clip;

/// A tool and its arguments for reading and for writing.
struct Tool {
    program: &'static str,
    read: &'static [&'static str],
    write: &'static [&'static str],
}

const WAYLAND: &[Tool] = &[Tool {
    program: "wl-paste",
    read: &["--no-newline"],
    write: &[],
}];
const WAYLAND_COPY: &str = "wl-copy";
const X11: &[Tool] = &[
    Tool {
        program: "xclip",
        read: &["-selection", "clipboard", "-o"],
        write: &["-selection", "clipboard", "-i"],
    },
    Tool {
        program: "xsel",
        read: &["--clipboard", "--output"],
        write: &["--clipboard", "--input"],
    },
];

fn session_set(var: &str) -> bool {
    std::env::var_os(var).is_some_and(|v| !v.is_empty())
}

/// The programs to try, in order, for the session this process runs in.
fn candidates(write: bool) -> Result<Vec<(&'static str, &'static [&'static str])>, PlatformError> {
    let mut list: Vec<(&'static str, &'static [&'static str])> = Vec::new();
    if session_set("WAYLAND_DISPLAY") {
        if write {
            list.push((WAYLAND_COPY, &[]));
        } else {
            list.extend(WAYLAND.iter().map(|t| (t.program, t.read)));
        }
    }
    if session_set("DISPLAY") {
        list.extend(
            X11.iter()
                .map(|t| (t.program, if write { t.write } else { t.read })),
        );
    }
    if list.is_empty() {
        return Err(PlatformError::Failed("no graphical session".into()));
    }
    Ok(list)
}

fn run(write: bool, input: Option<&[u8]>) -> Result<Vec<u8>, PlatformError> {
    for (program, args) in candidates(write)? {
        let mut cmd = Command::new(program);
        cmd.args(args);
        match run_clipboard_tool(cmd, input, !write) {
            Ok(ToolRun::Done(out)) => return Ok(out),
            // Nothing to read (an empty clipboard, or not text): not a failure of the clipboard.
            Ok(ToolRun::Failed) if !write => return Ok(Vec::new()),
            Ok(ToolRun::Failed) => continue,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(PlatformError::Failed(format!("{program}: {e}"))),
        }
    }
    Err(PlatformError::Failed(
        "no clipboard tool (install wl-clipboard or xclip)".into(),
    ))
}

impl Clipboard for Clip {
    fn read(&self) -> Result<String, PlatformError> {
        Ok(String::from_utf8_lossy(&run(false, None)?).into_owned())
    }

    fn write(&self, text: &str) -> Result<(), PlatformError> {
        run(true, Some(text.as_bytes())).map(|_| ())
    }
}
