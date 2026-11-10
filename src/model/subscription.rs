use super::server::Server;

#[derive(Debug, Clone)]
pub struct SubscriptionInfo {
    pub used: u64,
    pub total: u64,
    pub expire: String,
}

#[derive(Debug, Clone)]
pub struct Subscription {
    pub name: String,
    pub servers: Vec<Server>,
    pub collapsed: bool,
    pub info: Option<SubscriptionInfo>,
}
