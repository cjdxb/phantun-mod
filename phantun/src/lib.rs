use std::ops::RangeInclusive;
use std::time::Duration;

pub mod firewall;
pub mod http;
pub mod ssh;
pub mod utils;

pub const UDP_TTL: Duration = Duration::from_secs(180);

// Client keepalive: after a random period of silence from the server, send up to
// `KEEPALIVE_PROBES` probes at random intervals, and close the connection if none
// of them is answered, so that a new one is made (e.g. after the public IP changed)
pub const KEEPALIVE_IDLE: RangeInclusive<Duration> =
    Duration::from_secs(15)..=Duration::from_secs(25);
pub const KEEPALIVE_INTERVAL: RangeInclusive<Duration> =
    Duration::from_secs(3)..=Duration::from_secs(6);
pub const KEEPALIVE_PROBES: usize = 3;
