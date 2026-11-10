//! The background part of elf-gate. On Windows it is built without a console window, so
//! starting it at logon or from the interface never flashes one.
#![cfg_attr(windows, windows_subsystem = "windows")]

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--supervise") {
        std::process::exit(elf_gate::platform::run_supervisor(&args[1..]));
    }
    std::process::exit(elf_gate::daemon::run(&args).await);
}
