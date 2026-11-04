use clap::{crate_version, Arg, ArgAction, Command};
use fake_tcp::packet::MAX_PACKET_LEN;
use fake_tcp::{Socket, Stack};
use log::{debug, error, info};
use phantun::firewall::{Firewall, Nat};
use phantun::http;
use phantun::utils::{assign_ipv6_address, new_udp_reuseport, shutdown_signal, udp_recv_pktinfo};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use tokio::sync::{Notify, RwLock};
use tokio::time;
use tokio_tun::TunBuilder;
use tokio_util::sync::CancellationToken;

use phantun::{KEEPALIVE_IDLE, KEEPALIVE_INTERVAL, KEEPALIVE_PROBES, UDP_TTL};
use rand::Rng;

#[tokio::main]
async fn main() -> io::Result<()> {
    pretty_env_logger::init();

    let matches = Command::new("Phantun Client")
        .version(crate_version!())
        .author("Datong Sun (github.com/dndx)")
        .arg(
            Arg::new("local")
                .short('l')
                .long("local")
                .required(true)
                .value_name("IP:PORT")
                .help("Sets the IP and port where Phantun Client listens for incoming UDP datagrams, IPv6 address need to be specified as: \"[IPv6]:PORT\"")
        )
        .arg(
            Arg::new("remote")
                .short('r')
                .long("remote")
                .required(true)
                .value_name("IP or HOST NAME:PORT")
                .help("Sets the address or host name and port where Phantun Client connects to Phantun Server, IPv6 address need to be specified as: \"[IPv6]:PORT\"")
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
                .help("Sets the Tun interface IPv4 local address (O/S's end)")
                .default_value("192.168.200.1")
        )
        .arg(
            Arg::new("tun_peer")
                .long("tun-peer")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv4 destination (peer) address (Phantun Client's end). \
                       You will need to setup SNAT/MASQUERADE rules on your Internet facing interface \
                       in order for Phantun Client to connect to Phantun Server")
                .default_value("192.168.200.2")
        )
        .arg(
            Arg::new("ipv4_only")
                .long("ipv4-only")
                .short('4')
                .required(false)
                .help("Only use IPv4 address when connecting to remote")
                .action(ArgAction::SetTrue)
                .conflicts_with_all(["tun_local6", "tun_peer6"]),
        )
        .arg(
            Arg::new("tun_local6")
                .long("tun-local6")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv6 local address (O/S's end)")
                .default_value("fcc8::1")
        )
        .arg(
            Arg::new("tun_peer6")
                .long("tun-peer6")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv6 destination (peer) address (Phantun Client's end). \
                       You will need to setup SNAT/MASQUERADE rules on your Internet facing interface \
                       in order for Phantun Client to connect to Phantun Server")
                .default_value("fcc8::2")
        )
        .arg(
            Arg::new("handshake_packet")
                .long("handshake-packet")
                .required(false)
                .value_name("PATH")
                .help("Specify a file, which, after TCP handshake, its content will be sent as the \
                      first data packet to the server.\n\
                      Note: ensure this file's size does not exceed the MTU of the outgoing interface. \
                      The content is always sent out in a single packet and will not be further segmented")
        )
        .arg(
            Arg::new("iface")
                .long("iface")
                .required(false)
                .value_name("IFACE")
                .help("Sets the Internet facing interface. When set, Phantun Client enables IP forwarding \
                       and adds the required MASQUERADE rules on startup, and removes the rules on exit")
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
            Arg::new("http_host")
                .long("http-host")
                .required(false)
                .value_name("HOST")
                .help("Sets the Host header used by --fake-http and --http-handshake")
        )
        .arg(
            Arg::new("fake_http")
                .long("fake-http")
                .required(false)
                .help("After receiving SYN + ACK, send HTTP request decoys with a limited TTL, \
                       so middleboxes on the path see an HTTP connection. Decoys reaching the server are ignored")
                .action(ArgAction::SetTrue)
                .requires("http_host")
        )
        .arg(
            Arg::new("fake_ttl")
                .long("fake-ttl")
                .required(false)
                .value_name("TTL")
                .help("Number of hops the --fake-http decoys survive after leaving this host")
                .value_parser(clap::value_parser!(u8).range(1..255))
                .default_value("3")
        )
        .arg(
            Arg::new("fake_repeat")
                .long("fake-repeat")
                .required(false)
                .value_name("N")
                .help("Number of --fake-http decoys sent per connection")
                .value_parser(clap::value_parser!(usize))
                .default_value("2")
        )
        .arg(
            Arg::new("http_handshake")
                .long("http-handshake")
                .required(false)
                .help("After TCP handshake, exchange a real HTTP request/response with the server \
                       before forwarding any UDP traffic. The server must also be started with --http-handshake")
                .action(ArgAction::SetTrue)
                .requires("http_host")
        )
        .get_matches();

    let local_addr: SocketAddr = matches
        .get_one::<String>("local")
        .unwrap()
        .parse()
        .expect("bad local address");

    let ipv4_only = matches.get_flag("ipv4_only");

    let remote_addr = tokio::net::lookup_host(matches.get_one::<String>("remote").unwrap())
        .await
        .expect("bad remote address or host")
        .find(|addr| !ipv4_only || addr.is_ipv4())
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
    let handshake_packet: Option<Vec<u8>> = matches
        .get_one::<String>("handshake_packet")
        .map(fs::read)
        .transpose()?;
    let http_request = matches
        .get_one::<String>("http_host")
        .map(|host| http::request(host));
    let http_handshake = matches.get_flag("http_handshake");

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

    if remote_addr.is_ipv6() {
        assign_ipv6_address(tun[0].name(), tun_local6.unwrap(), tun_peer6.unwrap());
    }

    info!("Created TUN device {}", tun[0].name());

    let _firewall = matches
        .get_one::<String>("iface")
        .map(|iface| {
            Firewall::setup(
                matches.get_one::<String>("fw_backend").unwrap(),
                iface,
                tun[0].name(),
                Nat::Masquerade {
                    peer: tun_peer,
                    peer6: tun_peer6.filter(|_| remote_addr.is_ipv6()),
                },
            )
        })
        .transpose()
        .map_err(io::Error::other)?;

    let udp_sock = Arc::new(new_udp_reuseport(local_addr));
    let connections = Arc::new(RwLock::new(HashMap::<SocketAddr, Arc<Socket>>::new()));

    let mut stack = Stack::new(tun, tun_peer, tun_peer6);
    if matches.get_flag("fake_http") {
        stack.set_fake_packet(
            http_request.as_ref().unwrap(),
            // +1 because packets coming out of the Tun interface are forwarded
            // by the kernel, which decrements TTL once before they leave this host
            matches.get_one::<u8>("fake_ttl").unwrap() + 1,
            *matches.get_one::<usize>("fake_repeat").unwrap(),
        );
    }

    let main_loop = tokio::spawn(async move {
        let mut buf_r = [0u8; MAX_PACKET_LEN];

        loop {
            let (size, udp_remote_addr, udp_local_addr) = udp_recv_pktinfo(&udp_sock, &mut buf_r).await?;
            // seen UDP packet to listening socket, this means:
            // 1. It is a new UDP connection, or
            // 2. It is some extra packets not filtered by more specific
            //    connected UDP socket yet
            if let Some(sock) = connections.read().await.get(&udp_remote_addr) {
                sock.send(&buf_r[..size]).await;
                continue;
            }

            info!("New UDP client from {}", udp_remote_addr);
            let sock = stack.connect(remote_addr).await;
            if sock.is_none() {
                error!("Unable to connect to remote {}", remote_addr);
                continue;
            }

            let sock = Arc::new(sock.unwrap());
            if http_handshake {
                if !http::client_handshake(&sock, http_request.as_ref().unwrap()).await {
                    error!("HTTP handshake with {} failed, closing connection.", sock);
                    continue;
                }

                debug!("HTTP handshake with {} done", sock);
            }

            if let Some(ref p) = handshake_packet {
                if sock.send(p).await.is_none() {
                    error!("Failed to send handshake packet to remote, closing connection.");
                    continue;
                }

                debug!("Sent handshake packet to: {}", sock);
            }

            // send first packet
            if sock.send(&buf_r[..size]).await.is_none() {
                continue;
            }

            assert!(connections
                .write()
                .await
                .insert(udp_remote_addr, sock.clone())
                .is_none());
            debug!("inserted fake TCP socket into connection table");

            // spawn "fastpath" UDP socket and task, this will offload main task
            // from forwarding UDP packets

            let packet_received = Arc::new(Notify::new());
            let inbound = Arc::new(Notify::new());
            let quit = CancellationToken::new();

            for i in 0..num_cpus {
                let sock = sock.clone();
                let quit = quit.clone();
                let packet_received = packet_received.clone();
                let inbound = inbound.clone();

                tokio::spawn(async move {
                    let mut buf_udp = [0u8; MAX_PACKET_LEN];
                    let mut buf_tcp = [0u8; MAX_PACKET_LEN];
                    // Always reply from the same address that the peer used to communicate with
                    // us. This avoids a frequent problem with IPv6 privacy extensions when we
                    // erroneously bind to wrong short-lived temporary address even if the peer
                    // explicitly used a persistent address to communicate to us.
                    //
                    // To do so, first bind to (<incoming packet dst_ip>, <local addr port>), and then
                    // connect to (<incoming packet src_ip>, <incoming packet src_port>).
                    let bind_addr = match (udp_remote_addr, udp_local_addr) {
                        (SocketAddr::V4(_), IpAddr::V4(udp_local_ipv4)) => {
                            SocketAddr::V4(SocketAddrV4::new(
                                udp_local_ipv4,
                                local_addr.port(),
                            ))
                        }
                        (SocketAddr::V6(udp_remote_addr), IpAddr::V6(udp_local_ipv6)) => {
                            SocketAddr::V6(SocketAddrV6::new(
                                udp_local_ipv6,
                                local_addr.port(),
                                udp_remote_addr.flowinfo(),
                                udp_remote_addr.scope_id(),
                            ))
                        }
                        (_, _) => {
                            panic!("unexpected family combination for udp_remote_addr={udp_remote_addr} and udp_local_addr={udp_local_addr}");
                        }
                    };
                    let udp_sock = new_udp_reuseport(bind_addr);
                    udp_sock.connect(udp_remote_addr).await.unwrap();

                    loop {
                        tokio::select! {
                            Ok(size) = udp_sock.recv(&mut buf_udp) => {
                                if sock.send(&buf_udp[..size]).await.is_none() {
                                    debug!("removed fake TCP socket from connections table");
                                    quit.cancel();
                                    return;
                                }

                                packet_received.notify_one();
                            },
                            res = sock.recv(&mut buf_tcp) => {
                                match res {
                                    Some(size) => {
                                        // anything from the server, keepalive ACKs included,
                                        // proves the path is still alive
                                        inbound.notify_one();

                                        // empty segments are not traffic, otherwise
                                        // keepalive would keep the connection open forever
                                        if size == 0 {
                                            continue;
                                        }

                                        // late duplicate of the HTTP handshake response
                                        if http_handshake && http::is_response(&buf_tcp[..size]) {
                                            continue;
                                        }

                                        if let Err(e) = udp_sock.send(&buf_tcp[..size]).await {
                                            error!("Unable to send UDP packet to {}: {}, closing connection", e, remote_addr);
                                            quit.cancel();
                                            return;
                                        }
                                    },
                                    None => {
                                        debug!("removed fake TCP socket from connections table");
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

            {
                let quit = quit.clone();
                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = time::sleep(rand::rng().random_range(KEEPALIVE_IDLE)) => {},
                            _ = inbound.notified() => continue,
                            _ = quit.cancelled() => return,
                        }

                        let mut answered = false;
                        for _ in 0..KEEPALIVE_PROBES {
                            if sock.send_keepalive().await.is_none() {
                                quit.cancel();
                                return;
                            }

                            tokio::select! {
                                _ = time::sleep(rand::rng().random_range(KEEPALIVE_INTERVAL)) => {},
                                _ = inbound.notified() => {
                                    answered = true;
                                    break;
                                },
                                _ = quit.cancelled() => return,
                            }
                        }

                        if !answered {
                            info!(
                                "No answer to {} keepalive probes, closing connection {}",
                                KEEPALIVE_PROBES, sock
                            );
                            quit.cancel();
                            return;
                        }
                    }
                });
            }

            let connections = connections.clone();
            tokio::spawn(async move {
                loop {
                    let read_timeout = time::sleep(UDP_TTL);
                    let packet_received_fut = packet_received.notified();

                    tokio::select! {
                        _ = read_timeout => {
                            info!("No traffic seen in the last {:?}, closing connection", UDP_TTL);
                            connections.write().await.remove(&udp_remote_addr);
                            debug!("removed fake TCP socket from connections table");

                            quit.cancel();
                            return;
                        },
                        _ = quit.cancelled() => {
                            connections.write().await.remove(&udp_remote_addr);
                            debug!("removed fake TCP socket from connections table");
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
