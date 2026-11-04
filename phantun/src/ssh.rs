//! SSH version exchange and key exchange init carried inside fake TCP segments.
//!
//! With `--ssh-handshake` the connection opens like a real OpenSSH session
//! (RFC 4253 sections 4.2 and 7.1):
//!
//! 1. The server sends its identification string as soon as it accepts the
//!    connection, and the client sends its own right after connecting.
//! 2. Each side sends an `SSH_MSG_KEXINIT` packet once it has the peer's
//!    identification string.
//!
//! Phantun consumes all four messages and then forwards UDP as usual. The key
//! exchange never continues past KEXINIT, so later datagrams are not SSH packets.

use fake_tcp::Socket;
use fake_tcp::packet::MAX_PACKET_LEN;
use log::info;
use rand::Rng;
use tokio::time;

/// Both sides send this as an entire segment, so the peer can recognize it
/// without buffering. RFC 4253 limits the line to 255 bytes and forbids CR,
/// LF, and NUL before the terminating CRLF.
///
/// The stock OpenSSH of Ubuntu 24.04 LTS, one of the most common SSH servers.
/// Real distribution builds carry a package suffix after the version, which
/// a bare upstream version string lacks. The KEXINIT algorithm lists below
/// match this version, so the banner and the HASSH fingerprint agree.
pub const IDENTIFICATION: &[u8] = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n";

const SSH_MSG_KEXINIT: u8 = 20;
/// Block size of the packet before any cipher is negotiated (RFC 4253 section 6).
const BLOCK_SIZE: usize = 8;

/// Long enough to ride out a congested link without retransmitting
/// identification strings that were not lost.
const TIMEOUT: time::Duration = time::Duration::from_millis(2500);
const RETRIES: usize = 3;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Side {
    Client,
    Server,
}

// Default algorithm lists of OpenSSH 9.6 (see IDENTIFICATION). The client
// host key list leaves out the certificate types so a KEXINIT fits in a
// single IPv6 segment (1440 bytes) with room to spare.
const KEX_COMMON: &str = "sntrup761x25519-sha512@openssh.com,\
curve25519-sha256,curve25519-sha256@libssh.org,\
ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,\
diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,\
diffie-hellman-group18-sha512,diffie-hellman-group14-sha256";
const HOST_KEY_CLIENT: &str = "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,\
ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256";
const HOST_KEY_SERVER: &str = "rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ssh-ed25519";
const CIPHERS: &str = "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,\
aes128-gcm@openssh.com,aes256-gcm@openssh.com";
const MACS: &str = "umac-64-etm@openssh.com,umac-128-etm@openssh.com,\
hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,\
umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1";
const COMPRESSION: &str = "none,zlib@openssh.com";

pub fn is_identification(buf: &[u8]) -> bool {
    buf == IDENTIFICATION
}

/// The identification string without its CRLF, for logging.
pub fn identification_line() -> &'static str {
    std::str::from_utf8(IDENTIFICATION).unwrap().trim_end()
}

/// Builds an unencrypted `SSH_MSG_KEXINIT` binary packet with a fresh random
/// cookie and padding, so no two connections send the same bytes.
pub fn kexinit(side: Side) -> Vec<u8> {
    let mut rng = rand::rng();
    let (kex_suffix, host_key) = match side {
        Side::Client => (",ext-info-c,kex-strict-c-v00@openssh.com", HOST_KEY_CLIENT),
        Side::Server => (",ext-info-s,kex-strict-s-v00@openssh.com", HOST_KEY_SERVER),
    };
    let kex = format!("{KEX_COMMON}{kex_suffix}");

    let mut payload = vec![SSH_MSG_KEXINIT];
    let mut cookie = [0u8; 16];
    rng.fill(&mut cookie);
    payload.extend_from_slice(&cookie);
    let name_lists = [
        kex.as_str(),
        host_key,
        CIPHERS,
        CIPHERS,
        MACS,
        MACS,
        COMPRESSION,
        COMPRESSION,
        "",
        "",
    ];
    for list in name_lists {
        payload.extend_from_slice(&(list.len() as u32).to_be_bytes());
        payload.extend_from_slice(list.as_bytes());
    }
    payload.push(0); // first_kex_packet_follows
    payload.extend_from_slice(&[0; 4]); // reserved

    // packet_length and padding_length come before the payload, and the
    // whole packet must be a multiple of the block size with at least 4
    // bytes of padding
    let mut padding = BLOCK_SIZE - (4 + 1 + payload.len()) % BLOCK_SIZE;
    if padding < 4 {
        padding += BLOCK_SIZE;
    }
    let packet_length = 1 + payload.len() + padding;

    let mut packet = Vec::with_capacity(4 + packet_length);
    packet.extend_from_slice(&(packet_length as u32).to_be_bytes());
    packet.push(padding as u8);
    packet.extend_from_slice(&payload);
    let start = packet.len();
    packet.resize(start + padding, 0);
    rng.fill(&mut packet[start..]);
    packet
}

/// Whether `buf` is exactly one unencrypted `SSH_MSG_KEXINIT` packet.
pub fn is_kexinit(buf: &[u8]) -> bool {
    if buf.len() < 6 || buf.len() % BLOCK_SIZE != 0 {
        return false;
    }
    let packet_length = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let padding = buf[4] as usize;
    packet_length == buf.len() - 4
        && padding >= 4
        && padding < packet_length
        && buf[5] == SSH_MSG_KEXINIT
}

/// Runs the client half of the exchange: sends the identification string
/// at once, answers the server's identification string with a KEXINIT, and
/// returns when both the server's identification string and KEXINIT have
/// arrived. Anything else received meanwhile is discarded.
///
/// On timeout the identification string is sent again. The server answers
/// every copy after the first with its identification string and KEXINIT,
/// which covers the loss of any message in either direction.
pub async fn client_handshake(sock: &Socket) -> bool {
    let kexinit = kexinit(Side::Client);
    let mut buf = [0u8; MAX_PACKET_LEN];
    let mut got_identification = false;
    let mut got_kexinit = false;

    for attempt in 1..=RETRIES {
        if sock.send(IDENTIFICATION).await.is_none() {
            return false;
        }
        info!(
            "SSH -> {}: identification \"{}\" (attempt {}/{})",
            sock,
            identification_line(),
            attempt,
            RETRIES
        );

        let deadline = time::Instant::now() + TIMEOUT;
        loop {
            match time::timeout_at(deadline, sock.recv(&mut buf)).await {
                Ok(Some(size)) => {
                    let segment = &buf[..size];
                    if is_identification(segment) {
                        info!("SSH <- {}: identification \"{}\"", sock, identification_line());
                        if !got_identification {
                            got_identification = true;
                            if sock.send(&kexinit).await.is_none() {
                                return false;
                            }
                            info!("SSH -> {}: KEXINIT ({} bytes)", sock, kexinit.len());
                        }
                    } else if is_kexinit(segment) {
                        info!("SSH <- {}: KEXINIT ({} bytes)", sock, size);
                        got_kexinit = true;
                    }

                    if got_identification && got_kexinit {
                        return true;
                    }
                }
                Ok(None) => return false,
                Err(_) => break,
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identification_matches_rfc4253_shape() {
        assert!(IDENTIFICATION.starts_with(b"SSH-2.0-"));
        assert!(IDENTIFICATION.ends_with(b"\r\n"));
        assert!(IDENTIFICATION.len() <= 255);
        let line = &IDENTIFICATION[..IDENTIFICATION.len() - 2];
        assert!(line.iter().all(|b| (32..127).contains(b)));
        // softwareversion, up to the space before the comments, must not
        // contain '-' (RFC 4253 section 4.2)
        let rest = line.strip_prefix(b"SSH-2.0-").unwrap();
        let software = rest.split(|&b| b == b' ').next().unwrap();
        assert_eq!(software, b"OpenSSH_9.6p1");
        assert!(!software.contains(&b'-'));
        assert!(is_identification(IDENTIFICATION));
        assert!(!is_identification(&IDENTIFICATION[..IDENTIFICATION.len() - 2]));
        let mut extra = IDENTIFICATION.to_vec();
        extra.extend_from_slice(b"extra");
        assert!(!is_identification(&extra));
    }

    /// Parses the name-lists of a KEXINIT packet, checking every length field.
    fn name_lists(packet: &[u8]) -> Vec<String> {
        let padding = packet[4] as usize;
        let payload = &packet[5..packet.len() - padding];
        assert_eq!(payload[0], SSH_MSG_KEXINIT);
        let mut rest = &payload[17..];
        let mut lists = Vec::new();
        for _ in 0..10 {
            let len = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
            lists.push(String::from_utf8(rest[4..4 + len].to_vec()).unwrap());
            rest = &rest[4 + len..];
        }
        assert_eq!(rest, [0, 0, 0, 0, 0]);
        lists
    }

    #[test]
    fn kexinit_is_a_well_formed_packet() {
        for side in [Side::Client, Side::Server] {
            let packet = kexinit(side);
            assert!(is_kexinit(&packet), "{side:?}");
            assert_eq!(packet.len() % BLOCK_SIZE, 0);
            assert!((4..4 + BLOCK_SIZE).contains(&(packet[4] as usize)));
            // fits one fake TCP segment over IPv6
            assert!(packet.len() <= MAX_PACKET_LEN - 40 - 20, "{}", packet.len());

            let lists = name_lists(&packet);
            // OpenSSH 9.6 predates ML-KEM, so it must not offer it
            assert!(lists[0].starts_with("sntrup761x25519-sha512@openssh.com,"));
            assert!(!lists[0].contains("mlkem"));
            assert!(lists[2].starts_with("chacha20-poly1305@openssh.com"));
            assert_eq!(lists[8], "");
            assert_eq!(lists[9], "");
        }

        let client = name_lists(&kexinit(Side::Client));
        let server = name_lists(&kexinit(Side::Server));
        assert!(client[0].ends_with(",ext-info-c,kex-strict-c-v00@openssh.com"));
        assert!(server[0].ends_with(",ext-info-s,kex-strict-s-v00@openssh.com"));
    }

    #[test]
    fn kexinit_bytes_differ_between_connections() {
        let a = kexinit(Side::Client);
        let b = kexinit(Side::Client);
        assert_eq!(a.len(), b.len());
        assert_ne!(a[6..22], b[6..22], "cookie must be random");
    }

    #[test]
    fn is_kexinit_rejects_other_packets() {
        let packet = kexinit(Side::Server);
        assert!(!is_kexinit(IDENTIFICATION));
        assert!(!is_kexinit(&packet[..packet.len() - BLOCK_SIZE]));
        let mut wrong_type = packet.clone();
        wrong_type[5] = 21; // SSH_MSG_NEWKEYS
        assert!(!is_kexinit(&wrong_type));
        let mut extra = packet.clone();
        extra.extend_from_slice(&[0; BLOCK_SIZE]);
        assert!(!is_kexinit(&extra));
    }

    #[test]
    fn handshake_messages_are_not_http_handshake_messages() {
        for msg in [IDENTIFICATION, &kexinit(Side::Client)] {
            assert!(!crate::http::is_request(msg));
            assert!(!crate::http::is_handshake_response(msg));
        }
    }
}
