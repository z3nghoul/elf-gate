//! Windows Defender Firewall through the COM API (`INetFwPolicy2`). `netsh` is not used: its
//! output is localised.

use crate::platform::{Firewall, FwAction, FwDirection, FwRule};
use std::path::Path;
use windows::core::{Interface, BSTR};
use windows::Win32::Foundation::{VARIANT_BOOL, VARIANT_FALSE, VARIANT_TRUE};
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, INetFwRules, NetFwPolicy2, NetFwRule, NET_FW_ACTION_ALLOW,
    NET_FW_ACTION_BLOCK, NET_FW_PROFILE2_ALL, NET_FW_RULE_DIR_IN, NET_FW_RULE_DIR_OUT,
};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
};
use windows::Win32::System::Ole::IEnumVARIANT;
use windows::Win32::System::Variant::VARIANT;

pub fn open() -> Option<Box<dyn Firewall>> {
    Some(Box::new(Com))
}

struct Com;

/// COM is initialised for the thread that makes the calls, and released again after them.
struct ComScope;

impl ComScope {
    fn enter() -> Result<Self, String> {
        // SAFETY: balanced by `CoUninitialize` in `Drop`; a thread that already has COM in
        // another mode answers with an error, which is reported, not ignored.
        unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }
            .ok()
            .map_err(|e| format!("COM: {e}"))?;
        Ok(ComScope)
    }
}

impl Drop for ComScope {
    fn drop(&mut self) {
        // SAFETY: pairs the successful `CoInitializeEx` of `enter`.
        unsafe { CoUninitialize() };
    }
}

fn err(e: windows::core::Error) -> String {
    e.to_string()
}

fn rule_set() -> Result<INetFwRules, String> {
    // SAFETY: plain COM activation of the system's firewall policy object.
    let policy: INetFwPolicy2 =
        unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER) }.map_err(err)?;
    // SAFETY: `policy` is a live COM object.
    unsafe { policy.Rules() }.map_err(err)
}

/// Every rule object of the set (the collection is enumerated through `IEnumVARIANT`).
fn each_rule(rules: &INetFwRules) -> Result<Vec<INetFwRule>, String> {
    // SAFETY: `rules` is live; the enumerator and the variants it yields are owned COM values
    // that are released when dropped. `Next` writes at most the one slot given.
    unsafe {
        let enumerator: IEnumVARIANT = rules._NewEnum().map_err(err)?.cast().map_err(err)?;
        let mut out = Vec::new();
        loop {
            let mut slot = [VARIANT::default()];
            let mut fetched = 0u32;
            let hr = enumerator.Next(&mut slot, &mut fetched);
            if hr.is_err() || fetched == 0 {
                break;
            }
            let Ok(unknown) = windows::core::IUnknown::try_from(&slot[0]) else {
                continue;
            };
            if let Ok(rule) = unknown.cast::<INetFwRule>() {
                out.push(rule);
            }
        }
        Ok(out)
    }
}

fn describe(rule: &INetFwRule) -> Option<FwRule> {
    // SAFETY: `rule` is a live COM object; the getters only read.
    unsafe {
        let direction = match rule.Direction().ok()? {
            NET_FW_RULE_DIR_IN => FwDirection::In,
            NET_FW_RULE_DIR_OUT => FwDirection::Out,
            _ => return None,
        };
        let action = match rule.Action().ok()? {
            NET_FW_ACTION_ALLOW => FwAction::Allow,
            NET_FW_ACTION_BLOCK => FwAction::Block,
            _ => return None,
        };
        Some(FwRule {
            name: rule.Name().ok()?.to_string(),
            program: rule
                .ApplicationName()
                .map(|b| b.to_string())
                .unwrap_or_default(),
            direction,
            action,
            enabled: rule.Enabled().map(|b| b.as_bool()).unwrap_or(false),
        })
    }
}

fn bool_of(b: bool) -> VARIANT_BOOL {
    if b {
        VARIANT_TRUE
    } else {
        VARIANT_FALSE
    }
}

impl Firewall for Com {
    fn rules(&self) -> Result<Vec<FwRule>, String> {
        let _com = ComScope::enter()?;
        Ok(each_rule(&rule_set()?)?
            .iter()
            .filter_map(describe)
            .collect())
    }

    fn add_allow(&self, name: &str, program: &Path, direction: FwDirection) -> Result<(), String> {
        let _com = ComScope::enter()?;
        let rules = rule_set()?;
        // SAFETY: COM activation of a new rule object, filled in with owned BSTRs before it is
        // handed to the rule set.
        unsafe {
            let rule: INetFwRule =
                CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER).map_err(err)?;
            rule.SetName(&BSTR::from(name)).map_err(err)?;
            rule.SetDescription(&BSTR::from("elf-gate")).map_err(err)?;
            rule.SetApplicationName(&BSTR::from(program.as_os_str().to_string_lossy().as_ref()))
                .map_err(err)?;
            rule.SetDirection(match direction {
                FwDirection::In => NET_FW_RULE_DIR_IN,
                FwDirection::Out => NET_FW_RULE_DIR_OUT,
            })
            .map_err(err)?;
            rule.SetAction(NET_FW_ACTION_ALLOW).map_err(err)?;
            rule.SetProfiles(NET_FW_PROFILE2_ALL.0).map_err(err)?;
            rule.SetEnabled(bool_of(true)).map_err(err)?;
            rules.Add(&rule).map_err(err)
        }
    }

    fn set_program(&self, rule: &FwRule, program: &Path) -> Result<(), String> {
        let _com = ComScope::enter()?;
        for object in each_rule(&rule_set()?)? {
            if describe(&object).as_ref() == Some(rule) {
                // SAFETY: `object` is a live rule of the set; the new value is an owned BSTR.
                return unsafe {
                    object.SetApplicationName(&BSTR::from(
                        program.as_os_str().to_string_lossy().as_ref(),
                    ))
                }
                .map_err(err);
            }
        }
        Err("the rule is gone".into())
    }

    fn remove_by_name(&self, name: &str) -> Result<(), String> {
        let _com = ComScope::enter()?;
        // SAFETY: `Remove` takes the rule name as an owned BSTR.
        unsafe { rule_set()?.Remove(&BSTR::from(name)) }.map_err(err)
    }
}
