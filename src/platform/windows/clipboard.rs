//! The clipboard through the Windows API: `CF_UNICODETEXT`, no helper process.

use crate::platform::{Clipboard, PlatformError, CLIPBOARD_MAX};
use std::time::{Duration, Instant};
use windows::Win32::Foundation::{GlobalFree, HANDLE, HGLOBAL};
use windows::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardData, IsClipboardFormatAvailable, OpenClipboard,
    SetClipboardData,
};
use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};
use windows::Win32::System::Ole::CF_UNICODETEXT;

/// Another program may hold the clipboard for a moment: ask again for this long.
const OPEN_TIMEOUT: Duration = Duration::from_secs(1);

pub struct Clip;

/// The clipboard, open for this thread until the guard is dropped.
struct Open;

impl Open {
    fn new() -> Result<Self, PlatformError> {
        let deadline = Instant::now() + OPEN_TIMEOUT;
        loop {
            // SAFETY: no window handle: the clipboard belongs to the current task.
            match unsafe { OpenClipboard(None) } {
                Ok(()) => return Ok(Open),
                Err(e) if Instant::now() >= deadline => {
                    return Err(PlatformError::Failed(format!("OpenClipboard: {e}")))
                }
                Err(_) => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    }
}

impl Drop for Open {
    fn drop(&mut self) {
        // SAFETY: it was opened by this thread.
        let _ = unsafe { CloseClipboard() };
    }
}

impl Clipboard for Clip {
    fn read(&self) -> Result<String, PlatformError> {
        let _open = Open::new()?;
        // SAFETY: the clipboard is open; the format is checked before the data are asked for.
        unsafe {
            if IsClipboardFormatAvailable(u32::from(CF_UNICODETEXT.0)).is_err() {
                return Ok(String::new());
            }
            let handle = GetClipboardData(u32::from(CF_UNICODETEXT.0))
                .map_err(|e| PlatformError::Failed(format!("GetClipboardData: {e}")))?;
            let global = HGLOBAL(handle.0);
            let ptr = GlobalLock(global).cast::<u16>();
            if ptr.is_null() {
                return Err(PlatformError::Failed("GlobalLock failed".into()));
            }
            // The text ends with a NUL (or at the size the system holds, whichever is first).
            let limit = CLIPBOARD_MAX as usize / 2;
            let mut len = 0;
            while len < limit && *ptr.add(len) != 0 {
                len += 1;
            }
            let text = String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len));
            let _ = GlobalUnlock(global);
            Ok(text)
        }
    }

    fn write(&self, text: &str) -> Result<(), PlatformError> {
        let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
        let bytes = wide.len() * 2;
        let _open = Open::new()?;
        // SAFETY: the memory is ours until `SetClipboardData` succeeds, then the system owns it.
        unsafe {
            EmptyClipboard().map_err(|e| PlatformError::Failed(format!("EmptyClipboard: {e}")))?;
            let global = GlobalAlloc(GMEM_MOVEABLE, bytes)
                .map_err(|e| PlatformError::Failed(format!("GlobalAlloc: {e}")))?;
            let ptr = GlobalLock(global).cast::<u16>();
            if ptr.is_null() {
                let _ = GlobalFree(Some(global));
                return Err(PlatformError::Failed("GlobalLock failed".into()));
            }
            std::ptr::copy_nonoverlapping(wide.as_ptr(), ptr, wide.len());
            let _ = GlobalUnlock(global);
            if let Err(e) = SetClipboardData(u32::from(CF_UNICODETEXT.0), Some(HANDLE(global.0))) {
                let _ = GlobalFree(Some(global));
                return Err(PlatformError::Failed(format!("SetClipboardData: {e}")));
            }
        }
        Ok(())
    }
}
