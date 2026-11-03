use std::time::Duration;

pub mod firewall;
pub mod http;
pub mod utils;

pub const UDP_TTL: Duration = Duration::from_secs(180);
