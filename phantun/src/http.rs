//! HTTP/1.1 bytes carried inside fake TCP segments.
//!
//! The handshake request and response are exchanged once, then consumed by
//! Phantun. With `--http-payload`, every later UDP datagram is its own complete
//! HTTP message in a single segment: a POST toward the server, a 200 back.

use fake_tcp::Socket;
use fake_tcp::packet::MAX_PACKET_LEN;
use log::warn;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::time;

static OVERSIZE_WARNED: AtomicBool = AtomicBool::new(false);

const REQUEST_PREFIX: &[u8] = b"GET / HTTP/1.1\r\n";
const WRAP_REQUEST_PREFIX: &[u8] = b"POST / HTTP/1.1\r\n";
const RESPONSE_PREFIX: &[u8] = b"HTTP/1.1 200 OK\r\n";
pub const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\n\
    Content-Type: application/octet-stream\r\n\
    Connection: keep-alive\r\n\r\n";

const TIMEOUT: time::Duration = time::Duration::from_secs(1);
const RETRIES: usize = 3;

pub fn request(host: &str) -> Vec<u8> {
    format!(
        "GET / HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
         (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36\r\n\
         Accept: */*\r\n\
         Connection: keep-alive\r\n\r\n"
    )
    .into_bytes()
}

pub fn is_request(buf: &[u8]) -> bool {
    buf.starts_with(REQUEST_PREFIX)
}

/// Returns the value of the `Host` header of an HTTP request, if any.
pub fn request_host(buf: &[u8]) -> Option<String> {
    String::from_utf8_lossy(buf).lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("host")
            .then(|| value.trim().to_string())
    })
}

/// The single handshake reply, with no body. Wrapped UDP responses also start
/// with [`RESPONSE_PREFIX`] but carry `Content-Length` and a body.
pub fn is_handshake_response(buf: &[u8]) -> bool {
    buf == RESPONSE
}

/// One UDP datagram as a complete POST. `Content-Length` is the body size,
/// so the peer can recover it from this segment alone.
pub fn wrap_request(host: &str, body: &[u8]) -> Vec<u8> {
    let mut packet = format!(
        "POST / HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Type: application/octet-stream\r\n\
         Content-Length: {}\r\n\
         Connection: keep-alive\r\n\r\n",
        body.len()
    )
    .into_bytes();
    packet.extend_from_slice(body);
    packet
}

/// One UDP datagram as a complete `200` response.
pub fn wrap_response(body: &[u8]) -> Vec<u8> {
    let mut packet = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/octet-stream\r\n\
         Content-Length: {}\r\n\
         Connection: keep-alive\r\n\r\n",
        body.len()
    )
    .into_bytes();
    packet.extend_from_slice(body);
    packet
}

/// Warns, once per process, when a wrapped datagram is too large for the
/// peer to read in one packet. The peer drops such packets without a trace.
pub fn warn_if_oversized(sock: &Socket, packet: &[u8]) {
    let max = sock.max_payload_len();
    if packet.len() > max && !OVERSIZE_WARNED.swap(true, Ordering::Relaxed) {
        warn!(
            "{}: HTTP wrapped packet of {} bytes exceeds the {} byte limit and will be dropped by \
             the peer. Lower the MTU of the UDP application by at least {} bytes. Further \
             oversized packets are not logged",
            sock,
            packet.len(),
            max,
            packet.len() - max
        );
    }
}

pub fn unwrap_request(buf: &[u8]) -> Option<&[u8]> {
    unwrap_message(buf, WRAP_REQUEST_PREFIX)
}

pub fn unwrap_response(buf: &[u8]) -> Option<&[u8]> {
    unwrap_message(buf, RESPONSE_PREFIX)
}

fn unwrap_message<'a>(buf: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if !buf.starts_with(prefix) {
        return None;
    }
    let header_end = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let header = std::str::from_utf8(&buf[..header_end]).ok()?;
    let body = &buf[header_end + 4..];
    let mut content_length = None;
    for line in header.split("\r\n") {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return None;
            }
            content_length = Some(value.trim().parse::<usize>().ok()?);
        }
    }
    let content_length = content_length?;
    (body.len() == content_length).then_some(body)
}

/// Sends `request` and waits for the server's response, retransmitting on timeout.
/// Anything else received meanwhile is discarded.
pub async fn client_handshake(sock: &Socket, request: &[u8]) -> bool {
    let mut buf = [0u8; MAX_PACKET_LEN];

    for _ in 0..RETRIES {
        if sock.send(request).await.is_none() {
            return false;
        }

        let deadline = time::Instant::now() + TIMEOUT;
        loop {
            match time::timeout_at(deadline, sock.recv(&mut buf)).await {
                Ok(Some(size)) if is_handshake_response(&buf[..size]) => return true,
                Ok(Some(_)) => continue,
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
    fn wraps_each_datagram_in_its_own_message() {
        let body = b"\r\n\r\nGET / HTTP/1.1\r\n\0\xff";
        let request = wrap_request("www.example.com", body);
        assert_eq!(unwrap_request(&request), Some(body.as_slice()));
        assert!(unwrap_response(&request).is_none());

        // 4-digit Content-Length, same overhead as a full-size datagram.
        let full = vec![0u8; 1300];
        let request = wrap_request("www.example.com", &full);
        assert_eq!(unwrap_request(&request), Some(full.as_slice()));
        assert_eq!(request.len() - full.len(), 128);
        let response = wrap_response(&full);
        assert_eq!(unwrap_response(&response), Some(full.as_slice()));
        assert_eq!(response.len() - full.len(), 105);
        assert!(unwrap_request(&response).is_none());
        assert!(!is_handshake_response(&response));
    }

    #[test]
    fn rejects_a_body_that_does_not_match_content_length() {
        let mut packet = wrap_request("h", b"abcd");
        assert!(unwrap_request(&packet[..packet.len() - 1]).is_none());
        packet.push(1);
        assert!(unwrap_request(&packet).is_none());
    }

    #[test]
    fn handshake_messages_are_not_wrapped_datagrams() {
        let handshake = request("www.example.com");
        assert!(is_request(&handshake));
        assert!(unwrap_request(&handshake).is_none());
        assert!(is_handshake_response(RESPONSE));
        assert!(unwrap_response(RESPONSE).is_none());
    }
}
