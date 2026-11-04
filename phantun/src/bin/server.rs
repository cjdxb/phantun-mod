use clap::{crate_version, Arg, ArgAction, Command};
use fake_tcp::packet::MAX_PACKET_LEN;
use fake_tcp::{Socket, Stack};
use log::{debug, error, info};
use phantun::firewall::{Firewall, Nat};
use phantun::http;
use phantun::utils::{assign_ipv6_address, new_udp_reuseport, shutdown_signal};
use std::fs;
use std::io;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Notify;
use tokio::time;
use tokio_tun::TunBuilder;
use tokio_util::sync::CancellationToken;

use phantun::UDP_TTL;

#[tokio::main]
async fn main() -> io::Result<()> {
    pretty_env_logger::init();

    let matches = Command::new("Phantun Server")
        .version(crate_version!())
        .author("Datong Sun (github.com/dndx)")
        .arg(
            Arg::new("local")
                .short('l')
                .long("local")
                .required(true)
                .value_name("PORT")
                .help("Sets the port where Phantun Server listens for incoming Phantun Client TCP connections")
        )
        .arg(
            Arg::new("remote")
                .short('r')
                .long("remote")
                .required(true)
                .value_name("IP or HOST NAME:PORT")
                .help("Sets the address or host name and port where Phantun Server forwards UDP packets to, IPv6 address need to be specified as: \"[IPv6]:PORT\"")
        )
        .arg(
            Arg::new("tun")
                .long("tun")
                .required(false)
                .value_name("tunX")
                .help("Sets the Tun interface name, if absent, pick the next available name")
                .default_value("")
        )
        .arg(
            Arg::new("tun_local")
                .long("tun-local")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface local address (O/S's end)")
                .default_value("192.168.201.1")
        )
        .arg(
            Arg::new("tun_peer")
                .long("tun-peer")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface destination (peer) address (Phantun Server's end). \
                       You will need to setup DNAT rules to this address in order for Phantun Server \
                       to accept TCP traffic from Phantun Client")
                .default_value("192.168.201.2")
        )
        .arg(
            Arg::new("ipv4_only")
                .long("ipv4-only")
                .short('4')
                .required(false)
                .help("Do not assign IPv6 addresses to Tun interface")
                .action(ArgAction::SetTrue)
                .conflicts_with_all(["tun_local6", "tun_peer6"]),
        )
        .arg(
            Arg::new("tun_local6")
                .long("tun-local6")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv6 local address (O/S's end)")
                .default_value("fcc9::1")
        )
        .arg(
            Arg::new("tun_peer6")
                .long("tun-peer6")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv6 destination (peer) address (Phantun Client's end). \
                       You will need to setup SNAT/MASQUERADE rules on your Internet facing interface \
                       in order for Phantun Client to connect to Phantun Server")
                .default_value("fcc9::2")
        )
        .arg(
            Arg::new("handshake_packet")
                .long("handshake-packet")
                .required(false)
                .value_name("PATH")
                .help("Specify a file, which, after TCP handshake, its content will be sent as the \
                      first data packet to the client. With --http-handshake, the packet is sent \
                      after the HTTP response instead.\n\
                      Note: ensure this file's size does not exceed the MTU of the outgoing interface. \
                      The content is always sent out in a single packet and will not be further segmented")
        )
        .arg(
            Arg::new("iface")
                .long("iface")
                .required(false)
                .value_name("IFACE")
                .help("Sets the Internet facing interface. When set, Phantun Server enables IP forwarding \
                       and adds the required DNAT rules on startup, and removes the rules on exit")
        )
        .arg(
            Arg::new("fw_backend")
                .long("fw-backend")
                .required(false)
                .value_name("BACKEND")
                .help("Firewall backend used by --iface, \"auto\" uses nft when available")
                .value_parser(["auto", "nft", "iptables"])
                .default_value("auto")
                .requires("iface")
        )
        .arg(
            Arg::new("http_handshake")
                .long("http-handshake")
                .required(false)
                .help("Require every connection to start with the HTTP request sent by a Phantun Client \
                       started with --http-handshake, and answer it with an HTTP response. Connections \
                       sending other data first are closed")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("http_payload")
                .long("http-payload")
                .required(false)
                .help("Accept UDP payloads only from HTTP POST requests, and send each UDP payload \
                       back in its own HTTP response. No retransmission. The client must also be \
                       started with --http-payload")
                .action(ArgAction::SetTrue)
        )
        .get_matches();

    let local_port: u16 = matches
        .get_one::<String>("local")
        .unwrap()
        .parse()
        .expect("bad local port");

    let remote_addr = tokio::net::lookup_host(matches.get_one::<String>("remote").unwrap())
        .await
        .expect("bad remote address or host")
        .next()
        .expect("unable to resolve remote host name");

    info!("Remote address is: {}", remote_addr);

    let tun_local: Ipv4Addr = matches
        .get_one::<String>("tun_local")
        .unwrap()
        .parse()
        .expect("bad local address for Tun interface");
    let tun_peer: Ipv4Addr = matches
        .get_one::<String>("tun_peer")
        .unwrap()
        .parse()
        .expect("bad peer address for Tun interface");

    let (tun_local6, tun_peer6) = if matches.get_flag("ipv4_only") {
        (None, None)
    } else {
        (
            matches
                .get_one::<String>("tun_local6")
                .map(|v| v.parse().expect("bad local address for Tun interface")),
            matches
                .get_one::<String>("tun_peer6")
                .map(|v| v.parse().expect("bad peer address for Tun interface")),
        )
    };

    let tun_name = matches.get_one::<String>("tun").unwrap();
    let handshake_packet: Option<Arc<[u8]>> = matches
        .get_one::<String>("handshake_packet")
        .map(fs::read)
        .transpose()?
        .map(Arc::<[u8]>::from);
    let http_handshake = matches.get_flag("http_handshake");
    let http_payload = matches.get_flag("http_payload");

    let num_cpus = num_cpus::get();
    info!("{} cores available", num_cpus);

    let tun = TunBuilder::new()
        .name(tun_name) // if name is empty, then it is set by kernel.
        .up() // or set it up manually using `sudo ip link set <tun-name> up`.
        .address(tun_local)
        .destination(tun_peer)
        .queues(num_cpus)
        .build()
        .unwrap();

    if let (Some(tun_local6), Some(tun_peer6)) = (tun_local6, tun_peer6) {
        assign_ipv6_address(tun[0].name(), tun_local6, tun_peer6);
    }

    info!("Created TUN device {}", tun[0].name());

    let _firewall = matches
        .get_one::<String>("iface")
        .map(|iface| {
            Firewall::setup(
                matches.get_one::<String>("fw_backend").unwrap(),
                iface,
                tun[0].name(),
                Nat::Dnat {
                    port: local_port,
                    peer: tun_peer,
                    peer6: tun_peer6,
                },
            )
        })
        .transpose()
        .map_err(io::Error::other)?;

    //thread::sleep(time::Duration::from_secs(5));
    let mut stack = Stack::new(tun, tun_local, tun_local6);
    stack.listen(local_port);
    info!("Listening on {}", local_port);
    if http_handshake {
        info!("HTTP handshake enabled");
    }
    if http_payload {
        info!("HTTP payload enabled");
    }

    let main_loop = tokio::spawn(async move {
        let mut buf_udp = [0u8; MAX_PACKET_LEN];
        let mut buf_tcp = [0u8; MAX_PACKET_LEN];

        loop {
            let sock = Arc::new(stack.accept().await);
            info!("New connection: {}", sock);
            // With HTTP handshake the client discards every segment until the
            // response arrives, so this packet is sent by the worker afterwards.
            if !http_handshake {
                if let Some(p) = handshake_packet.as_deref() {
                    if send_payload(&sock, http_payload, p).await.is_none() {
                        error!("Failed to send handshake packet to remote, closing connection.");
                        continue;
                    }

                    debug!("Sent handshake packet to: {}", sock);
                }
            }

            let packet_received = Arc::new(Notify::new());
            let quit = CancellationToken::new();
            // shared by all workers, any of them may receive the HTTP request
            let http_done = Arc::new(AtomicBool::new(!http_handshake));
            let udp_sock = UdpSocket::bind(if remote_addr.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            })
            .await?;
            let local_addr = udp_sock.local_addr()?;
            drop(udp_sock);

            for i in 0..num_cpus {
                let sock = sock.clone();
                let quit = quit.clone();
                let packet_received = packet_received.clone();
                let http_done = http_done.clone();
                let handshake_packet = handshake_packet.clone();
                let udp_sock = new_udp_reuseport(local_addr);

                tokio::spawn(async move {
                    udp_sock.connect(remote_addr).await.unwrap();

                    loop {
                        tokio::select! {
                            Ok(size) = udp_sock.recv(&mut buf_udp) => {
                                if send_payload(&sock, http_payload, &buf_udp[..size]).await.is_none() {
                                    quit.cancel();
                                    return;
                                }

                                packet_received.notify_one();
                            },
                            res = sock.recv(&mut buf_tcp) => {
                                match res {
                                    Some(size) => {
                                        // HTTP handshake (or its retransmission) from client
                                        if http_handshake && http::is_request(&buf_tcp[..size]) {
                                            // set before replying: the client sends data only
                                            // after the response, possibly to another worker.
                                            // The handshake packet follows that response. The
                                            // client discards anything it reads before it, and a
                                            // retransmitted request repeats the response only.
                                            let first = !http_done.swap(true, Ordering::Relaxed);
                                            if sock.send(http::RESPONSE).await.is_none() {
                                                quit.cancel();
                                                return;
                                            }
                                            if first {
                                                if let Some(p) = handshake_packet.as_deref() {
                                                    if send_payload(&sock, http_payload, p).await.is_none() {
                                                        error!("Failed to send handshake packet to remote, closing connection.");
                                                        quit.cancel();
                                                        return;
                                                    }
                                                    debug!("Sent handshake packet to: {}", sock);
                                                }
                                            }

                                            info!(
                                                "HTTP handshake with {} done, Host {}",
                                                sock,
                                                http::request_host(&buf_tcp[..size])
                                                    .as_deref()
                                                    .unwrap_or("<none>")
                                            );
                                            continue;
                                        }

                                        if size > 0 && !http_done.load(Ordering::Relaxed) {
                                            error!("{} sent data before HTTP handshake, closing connection", sock);
                                            quit.cancel();
                                            return;
                                        }

                                        if size > 0 {
                                            let payload = if http_payload {
                                                match http::unwrap_request(&buf_tcp[..size]) {
                                                    Some(body) => body,
                                                    None => {
                                                        debug!("dropping TCP segment that is not an HTTP wrapped request");
                                                        continue;
                                                    }
                                                }
                                            } else {
                                                &buf_tcp[..size]
                                            };
                                            if let Err(e) = udp_sock.send(payload).await {
                                                error!("Unable to send UDP packet to {}: {}, closing connection", e, remote_addr);
                                                quit.cancel();
                                                return;
                                            }
                                        }
                                    },
                                    None => {
                                        quit.cancel();
                                        return;
                                    },
                                }

                                packet_received.notify_one();
                            },
                            _ = quit.cancelled() => {
                                debug!("worker {} terminated", i);
                                return;
                            },
                        };
                    }
                });
            }

            tokio::spawn(async move {
                loop {
                    let read_timeout = time::sleep(UDP_TTL);
                    let packet_received_fut = packet_received.notified();

                    tokio::select! {
                        _ = read_timeout => {
                            info!("No traffic seen in the last {:?}, closing connection", UDP_TTL);

                            quit.cancel();
                            return;
                        },
                        _ = packet_received_fut => {},
                    }
                }
            });
        }
    });

    tokio::select! {
        res = main_loop => res.unwrap(),
        _ = shutdown_signal() => {
            info!("Received shutdown signal, exiting");
            Ok(())
        },
    }
}

async fn send_payload(sock: &Socket, wrap: bool, payload: &[u8]) -> Option<()> {
    if wrap {
        let packet = http::wrap_response(payload);
        http::warn_if_oversized(sock, &packet);
        sock.send(&packet).await
    } else {
        sock.send(payload).await
    }
}
