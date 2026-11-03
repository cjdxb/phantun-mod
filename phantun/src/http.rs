//! HTTP/1.1 request/response exchanged right after the fake TCP handshake,
//! so that the connection looks like plain HTTP. Both packets are consumed
//! by Phantun and never forwarded as UDP.

use fake_tcp::Socket;
use fake_tcp::packet::MAX_PACKET_LEN;
use tokio::time;

const REQUEST_PREFIX: &[u8] = b"GET / HTTP/1.1\r\n";
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

pub fn is_response(buf: &[u8]) -> bool {
    buf.starts_with(RESPONSE_PREFIX)
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
                Ok(Some(size)) if is_response(&buf[..size]) => return true,
                Ok(Some(_)) => continue,
                Ok(None) => return false,
                Err(_) => break,
            }
        }
    }

    false
}
