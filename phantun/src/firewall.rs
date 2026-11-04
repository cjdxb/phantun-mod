//! Automatic NAT/forwarding rule management for the `--iface` option.
//!
//! Rules are added when [`Firewall::setup`] succeeds and removed when the
//! returned [`Firewall`] is dropped.

use log::{info, warn};
use std::fs;
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::{Command, Stdio};

pub enum Nat {
    /// Client: masquerade traffic from the Tun interface leaving through `iface`
    Masquerade {
        peer: Ipv4Addr,
        peer6: Option<Ipv6Addr>,
    },
    /// Server: DNAT TCP `port` arriving on `iface` to the Tun peer address
    Dnat {
        port: u16,
        peer: Ipv4Addr,
        peer6: Option<Ipv6Addr>,
    },
}

struct IptRule {
    cmd: &'static str,
    table: &'static str,
    chain: &'static str,
    spec: Vec<String>,
}

impl IptRule {
    fn args<'a>(&'a self, op: &'a str) -> Vec<&'a str> {
        let mut args = vec!["-w", "10", "-t", self.table, op, self.chain];
        args.extend(self.spec.iter().map(String::as_str));
        args
    }
}

pub struct Firewall {
    /// nft table name, also used as iptables rule comment
    name: String,
    nft: bool,
    ipt_rules: Vec<IptRule>,
}

impl Firewall {
    /// `backend` is one of `auto`, `nft` or `iptables`. `auto` uses nft when available.
    pub fn setup(backend: &str, iface: &str, tun: &str, nat: Nat) -> Result<Firewall, String> {
        let use_nft = match backend {
            "nft" => true,
            "iptables" => false,
            _ => Command::new("nft")
                .arg("--version")
                .output()
                .is_ok_and(|o| o.status.success()),
        };
        let name = format!("phantun_{tun}")
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        let peer6 = match nat {
            Nat::Masquerade { peer6, .. } | Nat::Dnat { peer6, .. } => peer6,
        };

        enable_forwarding("net/ipv4/ip_forward")?;
        if peer6.is_some() {
            enable_forwarding("net/ipv6/conf/all/forwarding")?;
        }

        let mut fw = Firewall {
            name,
            nft: false,
            ipt_rules: Vec::new(),
        };
        if use_nft {
            fw.setup_nft(iface, tun, &nat)?;
        } else {
            fw.setup_iptables(iface, tun, &nat)?;
        }

        info!(
            "Firewall rules {} added using {} on {}",
            fw.name,
            if use_nft { "nft" } else { "iptables" },
            iface
        );
        Ok(fw)
    }

    fn setup_nft(&mut self, iface: &str, tun: &str, nat: &Nat) -> Result<(), String> {
        let (peer, peer6) = match nat {
            Nat::Masquerade { peer, peer6 } | Nat::Dnat { peer, peer6, .. } => (peer, peer6),
        };
        // Packets that conntrack considers INVALID (e.g. a RST sent after the
        // connection's entry was flushed by an address change) skip NAT and
        // would leave `iface` with the Tun address as source. Runs after NAT,
        // so anything still carrying the Tun peer address is such a packet.
        let mut leak = format!(
            "    chain leak {{\n\
             \x20       type filter hook postrouting priority srcnat + 1; policy accept;\n\
             \x20       oifname \"{iface}\" ip saddr {peer} drop\n"
        );
        if let Some(peer6) = peer6 {
            leak += &format!("        oifname \"{iface}\" ip6 saddr {peer6} drop\n");
        }
        leak += "    }\n";

        let chain = match nat {
            Nat::Masquerade { .. } => format!(
                "    chain postrouting {{\n\
                 \x20       type nat hook postrouting priority srcnat; policy accept;\n\
                 \x20       iifname \"{tun}\" oifname \"{iface}\" masquerade\n\
                 \x20   }}\n"
            ),
            Nat::Dnat { port, peer, peer6 } => {
                let mut chain = format!(
                    "    chain prerouting {{\n\
                     \x20       type nat hook prerouting priority dstnat; policy accept;\n\
                     \x20       iifname \"{iface}\" tcp dport {port} dnat ip to {peer}\n"
                );
                if let Some(peer6) = peer6 {
                    chain += &format!(
                        "        iifname \"{iface}\" tcp dport {port} dnat ip6 to {peer6}\n"
                    );
                }
                chain + "    }\n"
            }
        };
        // declaring then deleting the table first atomically removes leftovers
        // from a previous run that was killed without cleaning up
        let script = format!(
            "table inet {name}\ndelete table inet {name}\ntable inet {name} {{\n{chain}{leak}}}\n",
            name = self.name
        );

        run("nft", &["-f", "-"], Some(&script))?;
        self.nft = true;
        Ok(())
    }

    fn setup_iptables(&mut self, iface: &str, tun: &str, nat: &Nat) -> Result<(), String> {
        let (peer, peer6) = match nat {
            Nat::Masquerade { peer, peer6 } | Nat::Dnat { peer, peer6, .. } => (peer, peer6),
        };
        let families = std::iter::once(("iptables", peer.to_string()))
            .chain(peer6.map(|p| ("ip6tables", p.to_string())));

        let mut rules = Vec::new();
        for (cmd, peer) in families {
            rules.push((cmd, "filter", "FORWARD", format!("-i {tun} -j ACCEPT")));
            rules.push((cmd, "filter", "FORWARD", format!("-o {tun} -j ACCEPT")));
            rules.push(match nat {
                Nat::Masquerade { .. } => (
                    cmd,
                    "nat",
                    "POSTROUTING",
                    format!("-s {peer} -o {iface} -j MASQUERADE"),
                ),
                Nat::Dnat { port, .. } => (
                    cmd,
                    "nat",
                    "PREROUTING",
                    format!("-p tcp -i {iface} --dport {port} -j DNAT --to-destination {peer}"),
                ),
            });
            // iptables has no hook after NAT, so drop what NAT cannot translate
            // instead: INVALID packets skip NAT entirely (e.g. a RST after the
            // conntrack entry was flushed), and on the server a connection
            // started from the Tun side has no DNAT to reverse. Inserted last
            // so they end up above the ACCEPT rules.
            let leak = format!("-i {tun} -o {iface} -m conntrack");
            rules.push((
                cmd,
                "filter",
                "FORWARD",
                format!("{leak} --ctstate INVALID -j DROP"),
            ));
            if let Nat::Dnat { .. } = nat {
                rules.push((
                    cmd,
                    "filter",
                    "FORWARD",
                    format!("{leak} --ctdir ORIGINAL -j DROP"),
                ));
            }
        }

        for (cmd, table, chain, spec) in rules {
            let rule = IptRule {
                cmd,
                table,
                chain,
                spec: spec
                    .split(' ')
                    .chain(["-m", "comment", "--comment", &self.name])
                    .map(str::to_owned)
                    .collect(),
            };

            // remove leftovers from a previous run that was killed without cleaning up
            for _ in 0..16 {
                if run(cmd, &rule.args("-D"), None).is_err() {
                    break;
                }
            }

            run(cmd, &rule.args("-I"), None)?;
            self.ipt_rules.push(rule);
        }

        Ok(())
    }
}

impl Drop for Firewall {
    fn drop(&mut self) {
        if self.nft
            && let Err(e) = run("nft", &["delete", "table", "inet", &self.name], None)
        {
            warn!("Unable to remove firewall rules: {}", e);
        }

        for rule in self.ipt_rules.iter().rev() {
            if let Err(e) = run(rule.cmd, &rule.args("-D"), None) {
                warn!("Unable to remove firewall rule: {}", e);
            }
        }

        info!("Firewall rules {} removed", self.name);
    }
}

fn enable_forwarding(key: &str) -> Result<(), String> {
    let path = format!("/proc/sys/{key}");
    let value = fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?;
    if value.trim() != "1" {
        fs::write(&path, "1").map_err(|e| format!("{path}: {e}"))?;
        info!("Enabled {}", key.replace('/', "."));
    }

    Ok(())
}

fn run(cmd: &str, args: &[&str], stdin: Option<&str>) -> Result<(), String> {
    let describe = || format!("`{} {}`", cmd, args.join(" "));
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{}: {}", describe(), e))?;

    if let Some(input) = stdin {
        // stdin handle is dropped right after writing, which closes the pipe
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .map_err(|e| format!("{}: {}", describe(), e))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("{}: {}", describe(), e))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{} failed: {}",
            describe(),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}
