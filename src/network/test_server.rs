use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::network::http_parser::HttpParser;

/// Controlled local HTTP test server for validating real traffic capture without external dependencies
pub struct ControlledTestServer {
    port: u16,
    running: Arc<AtomicBool>,
}

impl ControlledTestServer {
    pub fn new(port: u16) -> Self {
        Self {
            port,
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Starts the test server in a background worker thread
    pub fn start(&self) -> Result<(), std::io::Error> {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", self.port))?;
        listener.set_nonblocking(true)?;

        let running = Arc::clone(&self.running);
        running.store(true, Ordering::SeqCst);

        thread::spawn(move || {
            while running.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_millis(1500)));
                        let _ = stream.set_write_timeout(Some(Duration::from_millis(1500)));
                        Self::handle_client(&mut stream);
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => {
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    fn handle_client(stream: &mut TcpStream) {
        let mut buffer = [0u8; 8192];
        let bytes_read = match stream.read(&mut buffer) {
            Ok(n) if n > 0 => n,
            _ => return,
        };

        let req = match HttpParser::parse_request(&buffer[..bytes_read]) {
            Ok(r) => r,
            Err(_) => {
                let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
                return;
            }
        };

        match req.path.as_str() {
            "/api/chunked" => {
                let response = b"HTTP/1.1 200 OK\r\nServer: Sentinel-TestServer/1.0\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5;ext=first\r\nHello\r\n7;ext=second\r\n Chunk!\r\n0\r\nX-Trailer: verified\r\n\r\n";
                let _ = stream.write_all(response);
                let _ = stream.flush();
            }
            "/api/stream" => {
                let headers = b"HTTP/1.1 200 OK\r\nServer: Sentinel-TestServer/1.0\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
                let _ = stream.write_all(headers);
                let _ = stream.flush();

                for i in 1..=3 {
                    thread::sleep(Duration::from_millis(25));
                    let chunk = format!("{}\r\npart{}\r\n", 5, i);
                    let _ = stream.write_all(chunk.as_bytes());
                    let _ = stream.flush();
                }

                let end = b"0\r\n\r\n";
                let _ = stream.write_all(end);
                let _ = stream.flush();
            }
            "/api/range" => {
                let body = b"01234";
                let response = format!(
                    "HTTP/1.1 206 Partial Content\r\nServer: Sentinel-TestServer/1.0\r\nContent-Type: text/plain\r\nContent-Range: bytes 0-4/10\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let mut full = response.into_bytes();
                full.extend_from_slice(body);
                let _ = stream.write_all(&full);
                let _ = stream.flush();
            }
            "/api/conflicting" => {
                let raw = b"HTTP/1.1 200 OK\r\nServer: Sentinel-TestServer/1.0\r\nContent-Type: text/plain\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nHello\r\n0\r\n\r\n";
                let _ = stream.write_all(raw);
                let _ = stream.flush();
            }
            "/api/status" => {
                let body =
                    r#"{"service":"sentinel-core","status":"online","auth":"authorized-lab"}"#
                        .as_bytes();
                Self::send_json_response(stream, "HTTP/1.1 200 OK", body);
            }
            "/api/echo" => {
                let body = if req.body.is_empty() {
                    b"{\"echo\": \"empty\"}" as &[u8]
                } else {
                    &req.body
                };
                Self::send_json_response(stream, "HTTP/1.1 200 OK", body);
            }
            "/auth/login" => {
                let body =
                    r#"{"authenticated":true,"role":"auditor","scope":"127.0.0.1"}"#.as_bytes();
                let headers = format!(
                    "HTTP/1.1 200 OK\r\nServer: Sentinel-TestServer/1.0\r\nSet-Cookie: session_id=sentinel_token_abc123; HttpOnly; Path=/\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let mut full = headers.into_bytes();
                full.extend_from_slice(body);
                let _ = stream.write_all(&full);
                let _ = stream.flush();
            }
            "/admin/restricted" => {
                let body =
                    r#"{"error":"forbidden","message":"Requires privileged audit scope token"}"#
                        .as_bytes();
                Self::send_json_response(stream, "HTTP/1.1 403 Forbidden", body);
            }
            _ => {
                let body = b"Sentinel Test Server: Endpoint not found";
                let response = format!(
                    "HTTP/1.1 404 Not Found\r\nServer: Sentinel-TestServer/1.0\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let mut full = response.into_bytes();
                full.extend_from_slice(body);
                let _ = stream.write_all(&full);
                let _ = stream.flush();
            }
        }
    }

    fn send_json_response(stream: &mut TcpStream, status_line: &str, body: &[u8]) {
        let headers = format!(
            "{}\r\nServer: Sentinel-TestServer/1.0\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            status_line,
            body.len()
        );
        let mut full = headers.into_bytes();
        full.extend_from_slice(body);
        let _ = stream.write_all(&full);
        let _ = stream.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_controlled_server_lifecycle() {
        let server = ControlledTestServer::new(18989);
        assert!(server.start().is_ok());
        assert!(server.is_running());
        server.stop();
        thread::sleep(Duration::from_millis(50));
        assert!(!server.is_running());
    }
}
