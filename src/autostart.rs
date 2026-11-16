//! Start at logon. Where the entry lives depends on the traffic mode (Windows):
//! - TUN: a Task Scheduler task that runs `elf-gated` with the highest rights at logon, so TUN
//!   comes up without a UAC prompt. Creating it needs administrator rights: one UAC prompt, in
//!   a one-off elevated run of `elf-gated --autostart-task create <user>`.
//! - PROXY (or no task support, Linux): the plain entry, as before (`Run` value, desktop file).
//!
//! The plain entry stays in place until the task exists, so a declined prompt leaves a working
//! (unelevated) autostart behind.

use crate::platform::{self, quote_command, Autostart, LogonTask, PlatformError};

/// The flag of the one-off elevated run.
pub const TASK_FLAG: &str = "--autostart-task";

/// Why the entry is being brought in line with the settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    /// The user switched autostart or the mode: asking for rights is expected.
    UserAction,
    /// The daemon started: asks for rights only to repair a task that points elsewhere.
    Startup,
}

/// Where the entry ended up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    Off,
    /// The plain entry.
    Plain,
    /// The elevated task.
    Task,
    /// The task was asked for (the UAC prompt is open or was not shown); the plain entry
    /// stands in until it exists.
    TaskPending,
}

pub struct Backends<'a> {
    pub plain: &'a dyn Autostart,
    pub task: Option<&'a dyn LogonTask>,
    pub elevated: bool,
    /// Runs `elf-gated` again, elevated, with these arguments (UAC).
    pub elevate: &'a dyn Fn(&[String]) -> Result<(), PlatformError>,
}

fn text(e: PlatformError) -> String {
    e.to_string()
}

/// Brings the entries in line with `enabled` and the mode (`tun`). `command` starts `elf-gated`.
pub fn sync(
    b: &Backends,
    enabled: bool,
    tun: bool,
    command: &[String],
    user: &str,
    trigger: Trigger,
) -> Result<Placement, String> {
    let (true, true, Some(task)) = (enabled, tun, b.task) else {
        // The plain entry (or none), and no task.
        if enabled {
            b.plain.enable(command).map_err(text)?;
        } else if b.plain.is_enabled() {
            b.plain.disable().map_err(text)?;
        }
        if let Some(task) = b.task {
            remove_task(b, task, trigger == Trigger::UserAction)?;
        }
        return Ok(if enabled {
            Placement::Plain
        } else {
            Placement::Off
        });
    };

    let current = task.command().map_err(text)?;
    if current.as_deref() == Some(quote_command(command).as_str()) {
        drop_plain(b)?;
        return Ok(Placement::Task);
    }
    if b.elevated {
        task.create(user, command).map_err(text)?;
        drop_plain(b)?;
        return Ok(Placement::Task);
    }
    b.plain.enable(command).map_err(text)?;
    if trigger == Trigger::UserAction || current.is_some() {
        (b.elevate)(&[TASK_FLAG.into(), "create".into(), user.into()]).map_err(text)?;
    }
    Ok(Placement::TaskPending)
}

fn drop_plain(b: &Backends) -> Result<(), String> {
    if b.plain.is_enabled() {
        b.plain.disable().map_err(text)?;
    }
    Ok(())
}

/// Deletes the task. A task made with the highest rights may refuse a plain run: then the
/// one-off elevated run does it (only when the user asked for the change).
fn remove_task(b: &Backends, task: &dyn LogonTask, may_prompt: bool) -> Result<(), String> {
    if matches!(task.command(), Ok(None)) {
        return Ok(());
    }
    match task.delete() {
        Ok(()) => Ok(()),
        Err(_) if !b.elevated && may_prompt => {
            (b.elevate)(&[TASK_FLAG.into(), "delete".into()]).map_err(text)
        }
        Err(e) => Err(text(e)),
    }
}

/// The command line that starts the background process (what the entries run).
pub fn command() -> Option<Vec<String>> {
    crate::ipc::Spawn::default_for_current_exe().map(|sp| {
        let mut cmd = vec![sp.program.display().to_string()];
        cmd.extend(sp.args);
        cmd
    })
}

/// `DOMAIN\name` of the current user, as the task needs it.
pub fn current_user() -> String {
    let name = std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_default();
    match std::env::var("USERDOMAIN") {
        Ok(domain) if !domain.is_empty() => format!("{domain}\\{name}"),
        _ => name,
    }
}

/// Does the system have any start-at-logon entry of ours?
pub fn is_enabled() -> bool {
    platform::autostart().is_enabled()
        || platform::logon_task().is_some_and(|t| matches!(t.command(), Ok(Some(_))))
}

/// [`sync`] on the real system.
pub fn apply(enabled: bool, tun: bool, trigger: Trigger) -> Result<Placement, String> {
    let command = command().ok_or_else(|| crate::t!("eng.no_exe_path"))?;
    let plain = platform::autostart();
    let task = platform::logon_task();
    let privileges = platform::privileges();
    sync(
        &Backends {
            plain: plain.as_ref(),
            task: task.as_deref(),
            elevated: privileges.is_elevated(),
            elevate: &|args| privileges.relaunch_elevated(args),
        },
        enabled,
        tun,
        &command,
        &current_user(),
        trigger,
    )
}

/// `elf-gated --autostart-task create <user>` or `... delete`, started elevated: one run.
pub fn run_once(args: &[String]) -> i32 {
    let Some(task) = platform::logon_task() else {
        return 1;
    };
    if !platform::privileges().is_elevated() {
        tracing::error!("autostart task: administrator rights are needed");
        return 1;
    }
    let result = match args {
        [verb, user] if verb == "create" => command()
            .ok_or_else(|| PlatformError::Failed(crate::t!("eng.no_exe_path")))
            .and_then(|cmd| task.create(user, &cmd))
            // The plain entry of the same user is not needed any more.
            .map(|()| {
                let _ = platform::autostart().disable();
            }),
        [verb] if verb == "delete" => task.delete(),
        _ => Err(PlatformError::Failed(format!("bad arguments: {args:?}"))),
    };
    match result {
        Ok(()) => 0,
        Err(e) => {
            tracing::error!("autostart task: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::lock;
    use std::cell::RefCell;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Plain(Mutex<Option<Vec<String>>>);
    impl Autostart for Plain {
        fn is_enabled(&self) -> bool {
            lock(&self.0).is_some()
        }
        fn enable(&self, command: &[String]) -> Result<(), PlatformError> {
            *lock(&self.0) = Some(command.to_vec());
            Ok(())
        }
        fn disable(&self) -> Result<(), PlatformError> {
            *lock(&self.0) = None;
            Ok(())
        }
    }

    #[derive(Default)]
    struct Scheduler {
        task: Mutex<Option<String>>,
        user: Mutex<String>,
        delete_denied: bool,
    }
    impl LogonTask for Scheduler {
        fn command(&self) -> Result<Option<String>, PlatformError> {
            Ok(lock(&self.task).clone())
        }
        fn create(&self, user: &str, command: &[String]) -> Result<(), PlatformError> {
            *lock(&self.task) = Some(quote_command(command));
            *lock(&self.user) = user.into();
            Ok(())
        }
        fn delete(&self) -> Result<(), PlatformError> {
            if self.delete_denied {
                return Err(PlatformError::Failed("access denied".into()));
            }
            *lock(&self.task) = None;
            Ok(())
        }
    }

    fn cmd(path: &str) -> Vec<String> {
        vec![path.into()]
    }

    struct Run<'a> {
        plain: &'a Plain,
        task: Option<&'a Scheduler>,
        elevated: bool,
        prompts: RefCell<Vec<Vec<String>>>,
    }
    impl Run<'_> {
        fn sync(
            &self,
            enabled: bool,
            tun: bool,
            path: &str,
            t: Trigger,
        ) -> Result<Placement, String> {
            let elevate = |args: &[String]| {
                self.prompts.borrow_mut().push(args.to_vec());
                Ok(())
            };
            sync(
                &Backends {
                    plain: self.plain,
                    task: self.task.map(|t| t as &dyn LogonTask),
                    elevated: self.elevated,
                    elevate: &elevate,
                },
                enabled,
                tun,
                &cmd(path),
                r"PC\me",
                t,
            )
        }
    }
    fn setup<'a>(plain: &'a Plain, task: Option<&'a Scheduler>, elevated: bool) -> Run<'a> {
        Run {
            plain,
            task,
            elevated,
            prompts: RefCell::new(Vec::new()),
        }
    }

    #[test]
    fn proxy_mode_uses_the_plain_entry_and_removes_the_task() {
        let (plain, task) = (Plain::default(), Scheduler::default());
        *lock(&task.task) = Some(r"C:\old\elf-gated.exe".into());
        let r = setup(&plain, Some(&task), true);
        assert_eq!(
            r.sync(true, false, r"C:\elf\elf-gated.exe", Trigger::UserAction),
            Ok(Placement::Plain)
        );
        assert_eq!(
            lock(&plain.0).as_deref(),
            Some(&cmd(r"C:\elf\elf-gated.exe")[..])
        );
        assert!(lock(&task.task).is_none());
        assert!(r.prompts.borrow().is_empty(), "elevated already: no prompt");
    }

    #[test]
    fn tun_mode_asks_for_rights_once_and_keeps_the_plain_entry_until_the_task_exists() {
        let (plain, task) = (Plain::default(), Scheduler::default());
        let r = setup(&plain, Some(&task), false);
        assert_eq!(
            r.sync(true, true, r"C:\elf\elf-gated.exe", Trigger::UserAction),
            Ok(Placement::TaskPending)
        );
        assert_eq!(
            r.prompts.borrow().as_slice(),
            [vec![
                TASK_FLAG.to_string(),
                "create".into(),
                r"PC\me".into()
            ]]
        );
        assert!(plain.is_enabled(), "stands in while the prompt is open");

        // The elevated run created the task; the next sync moves over without a prompt.
        task.create(r"PC\me", &cmd(r"C:\elf\elf-gated.exe"))
            .unwrap();
        assert_eq!(
            r.sync(true, true, r"C:\elf\elf-gated.exe", Trigger::Startup),
            Ok(Placement::Task)
        );
        assert!(!plain.is_enabled());
        assert_eq!(r.prompts.borrow().len(), 1);
    }

    #[test]
    fn an_elevated_daemon_creates_the_task_itself() {
        let (plain, task) = (Plain::default(), Scheduler::default());
        let r = setup(&plain, Some(&task), true);
        assert_eq!(
            r.sync(true, true, r"C:\elf\elf-gated.exe", Trigger::UserAction),
            Ok(Placement::Task)
        );
        assert_eq!(*lock(&task.user), r"PC\me");
        assert!(r.prompts.borrow().is_empty());
    }

    #[test]
    fn a_task_for_a_moved_folder_is_repaired_at_startup_but_a_missing_one_is_not_asked_for() {
        let (plain, task) = (Plain::default(), Scheduler::default());
        let r = setup(&plain, Some(&task), false);
        assert_eq!(
            r.sync(true, true, r"C:\new\elf-gated.exe", Trigger::Startup),
            Ok(Placement::TaskPending)
        );
        assert!(
            r.prompts.borrow().is_empty(),
            "no task and no user action: no prompt"
        );

        *lock(&task.task) = Some(r"C:\old\elf-gated.exe".into());
        assert_eq!(
            r.sync(true, true, r"C:\new\elf-gated.exe", Trigger::Startup),
            Ok(Placement::TaskPending)
        );
        assert_eq!(
            r.prompts.borrow().len(),
            1,
            "stale path: ask once to update it"
        );
    }

    #[test]
    fn switching_autostart_off_removes_both_entries_and_asks_only_if_delete_is_refused() {
        let (plain, task) = (Plain::default(), Scheduler::default());
        plain.enable(&cmd("x")).unwrap();
        task.create("u", &cmd("x")).unwrap();
        let r = setup(&plain, Some(&task), false);
        assert_eq!(
            r.sync(false, true, "x", Trigger::UserAction),
            Ok(Placement::Off)
        );
        assert!(!plain.is_enabled() && lock(&task.task).is_none());
        assert!(r.prompts.borrow().is_empty());

        let denied = Scheduler {
            delete_denied: true,
            ..Scheduler::default()
        };
        denied.create("u", &cmd("x")).unwrap();
        let r = setup(&plain, Some(&denied), false);
        assert_eq!(
            r.sync(false, true, "x", Trigger::UserAction),
            Ok(Placement::Off)
        );
        assert_eq!(
            r.prompts.borrow().as_slice(),
            [vec![TASK_FLAG.to_string(), "delete".into()]]
        );
        // At startup nothing is asked for a leftover task.
        let r = setup(&plain, Some(&denied), false);
        assert!(r.sync(true, false, "x", Trigger::Startup).is_err());
        assert!(r.prompts.borrow().is_empty());
    }

    #[test]
    fn without_task_support_the_mode_does_not_matter() {
        let plain = Plain::default();
        let r = setup(&plain, None, false);
        assert_eq!(
            r.sync(true, true, "x", Trigger::UserAction),
            Ok(Placement::Plain)
        );
        assert!(plain.is_enabled());
        assert!(r.prompts.borrow().is_empty());
    }
}
