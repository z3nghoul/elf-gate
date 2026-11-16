//! The screen of one subscription: its name, URL, User-Agent, update interval, HWID, hidden
//! servers, and the actions "update" and "delete". A value that is not overridden is the default
//! from the settings and is marked so; an overridden one can be reset.

use super::*;
use crate::proto::Setting;
use crate::storage::SubscriptionConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubRow {
    Name,
    Url,
    UserAgent,
    Hours,
    Hwid,
    Hidden,
    Update,
    Delete,
}

impl SubRow {
    pub const ALL: [SubRow; 8] = [
        SubRow::Name,
        SubRow::Url,
        SubRow::UserAgent,
        SubRow::Hours,
        SubRow::Hwid,
        SubRow::Hidden,
        SubRow::Update,
        SubRow::Delete,
    ];

    /// What the row is, in plain words, for the line under the list.
    pub fn explain(self) -> String {
        crate::t!(match self {
            SubRow::Name => "explain.sub_name",
            SubRow::Url => "explain.sub_url",
            SubRow::UserAgent => "explain.sub_user_agent",
            SubRow::Hours => "explain.sub_hours",
            SubRow::Hwid => "explain.sub_hwid",
            SubRow::Hidden => "explain.sub_hidden",
            SubRow::Update => "explain.sub_update",
            SubRow::Delete => "explain.sub_delete",
        })
    }
}

/// Where a shown value comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Not a setting (name, URL, counts, actions).
    Fixed,
    /// The default from the settings.
    Default,
    /// Set for this subscription.
    Own,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubField {
    pub row: SubRow,
    pub label: String,
    pub value: String,
    pub origin: Origin,
}

impl AppState {
    /// Opens the screen of a subscription by its name; the manual group has none.
    pub fn open_subscription(&mut self, name: &str) {
        if !self.config.subscriptions.iter().any(|s| s.name == name) {
            self.set_status(crate::t!("status.no_sub_screen"));
            return;
        }
        self.sub_name = name.to_string();
        self.sub_cursor = 0;
        self.screen = Screen::Subscription;
    }

    pub fn sub_config(&self) -> Option<&SubscriptionConfig> {
        self.config
            .subscriptions
            .iter()
            .find(|s| s.name == self.sub_name)
    }

    pub fn sub_hidden_count(&self) -> usize {
        self.subs
            .iter()
            .find(|g| g.name == self.sub_name)
            .map_or(0, |g| g.servers.iter().filter(|s| s.hidden).count())
    }

    /// The rows in display order.
    pub fn sub_fields(&self) -> Vec<SubField> {
        let Some(sc) = self.sub_config() else {
            return Vec::new();
        };
        let d = &self.config.sub_defaults;
        let origin = |own: bool| if own { Origin::Own } else { Origin::Default };
        let field = |row, label: String, value: String, origin| SubField {
            row,
            label,
            value,
            origin,
        };
        let onoff = |b: bool| {
            if b {
                crate::t!("setting.on")
            } else {
                crate::t!("setting.off")
            }
        };
        vec![
            field(
                SubRow::Name,
                crate::t!("sub.name"),
                self.group_title(&sc.name),
                Origin::Fixed,
            ),
            field(
                SubRow::Url,
                crate::t!("sub.url"),
                sc.url.clone(),
                Origin::Fixed,
            ),
            field(
                SubRow::UserAgent,
                crate::t!("sub.user_agent"),
                sc.user_agent(d).to_string(),
                origin(sc.user_agent.is_some()),
            ),
            field(
                SubRow::Hours,
                crate::t!("sub.hours"),
                sc.hours(d).to_string(),
                origin(sc.auto_update_hours.is_some()),
            ),
            field(
                SubRow::Hwid,
                crate::t!("sub.hwid"),
                onoff(sc.sends_hwid(d)),
                origin(sc.send_hwid.is_some()),
            ),
            field(
                SubRow::Hidden,
                crate::t!("sub.hidden"),
                self.sub_hidden_count().to_string(),
                Origin::Fixed,
            ),
            field(
                SubRow::Update,
                crate::t!("sub.update"),
                String::new(),
                Origin::Fixed,
            ),
            field(
                SubRow::Delete,
                crate::t!("sub.delete"),
                String::new(),
                Origin::Fixed,
            ),
        ]
    }

    pub(super) fn sub_move(&mut self, delta: isize) {
        let len = self.sub_fields().len() as isize;
        if len > 0 {
            self.sub_cursor = (self.sub_cursor as isize + delta).clamp(0, len - 1) as usize;
        }
    }

    fn sub_row(&self) -> Option<SubRow> {
        self.sub_fields().get(self.sub_cursor).map(|f| f.row)
    }

    /// Enter on a row: edit, switch or run it.
    pub(super) fn sub_activate(&mut self) {
        let name = self.sub_name.clone();
        let Some(sc) = self.sub_config().cloned() else {
            return;
        };
        let d = self.config.sub_defaults.clone();
        match self.sub_row() {
            Some(SubRow::UserAgent) => {
                self.popup = Some(Popup::Input {
                    title: crate::t!("sub.input_ua"),
                    buf: sc.user_agent(&d).to_string(),
                    purpose: InputPurpose::SubUserAgent(name),
                });
            }
            Some(SubRow::Hours) => {
                self.popup = Some(Popup::Input {
                    title: crate::t!("sub.input_hours"),
                    buf: sc.hours(&d).to_string(),
                    purpose: InputPurpose::SubHours(name),
                });
            }
            // The default, then the opposite of it, then the default again.
            Some(SubRow::Hwid) => {
                let value = match sc.send_hwid {
                    None => Some(!d.send_hwid),
                    Some(_) => None,
                };
                self.send(Cmd::Set(Setting::SubscriptionHwid { name, value }));
            }
            Some(SubRow::Hidden) => {
                if self.sub_hidden_count() == 0 {
                    self.set_status(crate::t!("status.no_hidden"));
                } else {
                    self.show_hidden.insert(name);
                    self.screen = Screen::Main;
                    self.set_status(crate::t!(
                        "status.hidden_shown",
                        count = self.sub_hidden_count()
                    ));
                }
            }
            Some(SubRow::Update) => self.send(Cmd::UpdateSub(name)),
            Some(SubRow::Delete) => {
                if let Some(i) = self.subs.iter().position(|g| g.name == name) {
                    self.ask_delete_group(i);
                }
            }
            Some(SubRow::Name | SubRow::Url) | None => self.set_status(crate::t!("sub.fixed")),
        }
    }

    /// `r`: back to the default for the row.
    pub(super) fn sub_reset(&mut self) {
        let name = self.sub_name.clone();
        let set = match self.sub_row() {
            Some(SubRow::UserAgent) => Setting::SubscriptionUserAgent { name, value: None },
            Some(SubRow::Hours) => Setting::SubscriptionHours { name, hours: None },
            Some(SubRow::Hwid) => Setting::SubscriptionHwid { name, value: None },
            _ => return,
        };
        self.send(Cmd::Set(set));
    }

    /// The text typed for a User-Agent or an interval: empty means the default.
    pub(super) fn submit_sub_input(&mut self, purpose: InputPurpose, text: String) {
        let text = text.trim().to_string();
        let set = match purpose {
            InputPurpose::SubUserAgent(name) => Ok(Setting::SubscriptionUserAgent {
                name,
                value: (!text.is_empty()).then_some(text),
            }),
            InputPurpose::SubHours(name) => {
                if text.is_empty() {
                    Ok(Setting::SubscriptionHours { name, hours: None })
                } else {
                    text.parse::<u32>()
                        .map(|h| Setting::SubscriptionHours {
                            name,
                            hours: Some(h),
                        })
                        .map_err(|_| crate::t!("setting.err_int"))
                }
            }
            _ => return,
        };
        match set {
            Ok(s) => self.send(Cmd::Set(s)),
            Err(e) => self.popup = Some(Popup::Error(e)),
        }
    }
}
