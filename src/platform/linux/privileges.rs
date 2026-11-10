use crate::platform::{InvokingUser, PlatformError, Privileges};
use nix::unistd::{chown, geteuid, Gid, Uid, User};
use std::path::Path;

pub struct Elevation;

impl Privileges for Elevation {
    fn is_elevated(&self) -> bool {
        geteuid().is_root()
    }

    fn invoking_user(&self) -> Option<InvokingUser> {
        if !self.is_elevated() {
            return None;
        }
        let name = std::env::var("SUDO_USER")
            .ok()
            .filter(|n| !n.is_empty() && n != "root")?;
        let user = User::from_name(&name).ok().flatten()?;
        Some(InvokingUser {
            name,
            home: user.dir,
            uid: user.uid.as_raw(),
            gid: user.gid.as_raw(),
        })
    }

    fn chown_to_invoking_user(&self, path: &Path) -> Result<(), PlatformError> {
        let Some(user) = self.invoking_user() else {
            return Ok(());
        };
        chown(
            path,
            Some(Uid::from_raw(user.uid)),
            Some(Gid::from_raw(user.gid)),
        )
        .map_err(|e| PlatformError::Failed(format!("chown {}: {e}", path.display())))
    }

    fn relaunch_elevated(&self, _args: &[String]) -> Result<(), PlatformError> {
        // On Linux the user starts `sudo elf-gate` themselves; the program never calls sudo.
        Err(PlatformError::Unsupported("relaunch with elevated rights"))
    }
}
