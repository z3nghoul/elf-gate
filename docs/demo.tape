# Demo for the README. Needs vhs (https://github.com/charmbracelet/vhs) and a debug build
# (cargo build): the demo servers, pings and traffic are fake and exist only there.
# Run it from the repository root:  vhs docs/demo.tape
#
# Everything lives in a temporary folder (config, state, socket), so the real config of the
# machine is never read or written, and no tray icon or system proxy is touched.
Output docs/demo.gif

Set Theme "Catppuccin Mocha"
Set FontSize 15
Set Width 1200
Set Height 640
Set Padding 16
Set TypingSpeed 40ms
Set PlaybackSpeed 1

Hide
Type "T=$(mktemp -d /tmp/elfgate-demo.XXXX); mkdir -p -m 700 $T/c/elf-gate $T/s $T/r"
Enter
Type "printf '[proxy]\nset_system_proxy = false\n' > $T/c/elf-gate/config.toml"
Enter
Type "export PATH=$PWD/target/debug:$PATH ELF_GATE_DEMO=1 HOME=$T XDG_CONFIG_HOME=$T/c XDG_STATE_HOME=$T/s XDG_RUNTIME_DIR=$T/r; unset DBUS_SESSION_BUS_ADDRESS DISPLAY WAYLAND_DISPLAY"
Enter
Type "clear; elf-gate"
Enter
Sleep 3s
Type "p"
Wait+Screen@60s /backup/
Sleep 3s
Show

# ping everything, sort by ping, connect to the fastest server
Sleep 1s
Type "p"
Sleep 3s
Type "o"
Sleep 1500ms
Type "j"
Sleep 1s
Enter
Sleep 5s

# privacy mode hides hosts and keys on the screen
Ctrl+P
Sleep 2500ms
Ctrl+P
Sleep 1200ms

# rules
Type "r"
Sleep 2500ms
Type "j"
Sleep 600ms
Type "j"
Sleep 600ms
Type "j"
Sleep 1500ms
Escape
Sleep 1s

# settings, the first row is the language
Type "s"
Sleep 2500ms
Escape
Sleep 800ms

# help
Type "?"
Sleep 3s
Escape
Sleep 800ms

Hide
Type "Q"
Sleep 500ms
Type "y"
Sleep 800ms
Type "cd; rm -rf $T"
Enter
Show
