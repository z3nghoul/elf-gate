#![allow(dead_code)] // placeholder until stage 7

/// Routing model placeholder; the real rules arrive in stage 7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingMode {
    Exclude,
    Include,
}
