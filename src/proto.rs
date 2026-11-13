//! Per-protocol login attempts. Each fn returns Ok(true) on success.
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum Proto {
    Ftp,
    HttpBasic,
    Ssh,
}

/// Reads an FTP reply, handling multi-line replies ("ddd-" continuation lines);
/// returns the numeric code of the final line.
async fn ftp_reply(s: &mut TcpStream, to: Duration) -> Result<u16> {
    let mut acc = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        let n = timeout(to, s.read(&mut buf)).await??;
        if n == 0 {
            return Err(anyhow!("connection closed"));
        }
        acc.extend_from_slice(&buf[..n]);
        // a complete reply ends with a line "ddd " (space after the code)
        if let Some(code) = final_ftp_code(&acc) {
            return Ok(code);
        }
    }
}

/// Returns the code of a completed FTP reply, or None if more data is needed.
/// Operates on raw bytes (a reply line "ddd " ends the reply) so arbitrary,
/// non-UTF-8 input can never panic.
fn final_ftp_code(buf: &[u8]) -> Option<u16> {
    for line in buf.split(|&b| b == b'\n') {
        if line.len() >= 4 && line[3] == b' ' && line[0..3].iter().all(u8::is_ascii_digit) {
            let code = (line[0] - b'0') as u16 * 100
                + (line[1] - b'0') as u16 * 10
                + (line[2] - b'0') as u16;
            return Some(code);
        }
    }
    None
}

pub async fn ftp(host: &str, port: u16, user: &str, pass: &str, to: Duration) -> Result<bool> {
    let mut s = timeout(to, TcpStream::connect((host, port))).await??;
    let greet = ftp_reply(&mut s, to).await?;
    if greet != 220 {
        return Err(anyhow!("unexpected greeting: {greet}"));
    }
    s.write_all(format!("USER {user}\r\n").as_bytes()).await?;
    let c1 = ftp_reply(&mut s, to).await?;
    if c1 == 230 {
        let _ = s.write_all(b"QUIT\r\n").await;
        return Ok(true); // logged in with no password
    }
    if c1 != 331 {
        // 332 needs ACCT, 530 already denied, etc.
        let _ = s.write_all(b"QUIT\r\n").await;
        return Ok(false);
    }
    s.write_all(format!("PASS {pass}\r\n").as_bytes()).await?;
    let c2 = ftp_reply(&mut s, to).await?;
    let _ = s.write_all(b"QUIT\r\n").await;
    Ok(c2 == 230)
}

pub async fn http_basic(
    host: &str,
    port: u16,
    path: &str,
    user: &str,
    pass: &str,
    to: Duration,
) -> Result<bool> {
    let mut s = timeout(to, TcpStream::connect((host, port))).await??;
    let cred = STANDARD.encode(format!("{user}:{pass}"));
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Basic {cred}\r\nUser-Agent: cr4ckreap\r\nConnection: close\r\n\r\n"
    );
    s.write_all(req.as_bytes()).await?;
    let mut buf = [0u8; 512];
    let n = timeout(to, s.read(&mut buf)).await??;
    let status = String::from_utf8_lossy(&buf[..n]);
    let code: u16 = status
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    // 401/403 = denied; anything else 2xx/3xx = accepted
    Ok(code != 401 && code != 403 && code != 0)
}

struct NoVerify;

impl russh::client::Handler for NoVerify {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        _key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true) // auditing credentials, not the host key
    }
}

pub async fn ssh(host: &str, port: u16, user: &str, pass: &str, to: Duration) -> Result<bool> {
    let config = Arc::new(russh::client::Config::default());
    let connect = russh::client::connect(config, (host, port), NoVerify);
    let mut handle = match timeout(to, connect).await {
        Ok(Ok(h)) => h,
        Ok(Err(e)) => return Err(anyhow!("ssh connect: {e}")),
        Err(_) => return Err(anyhow!("ssh connect timeout")),
    };
    let res = timeout(to, handle.authenticate_password(user, pass))
        .await
        .map_err(|_| anyhow!("ssh auth timeout"))?
        .map_err(|e| anyhow!("ssh auth: {e}"))?;
    Ok(res.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuzz_ftp_parser_no_panic() {
        let mut x: u64 = 0xDEADBEEFCAFEBABE;
        for _ in 0..20_000 {
            x ^= x << 13; x ^= x >> 7; x ^= x << 17;
            let len = (x as usize) % 400;
            let buf: Vec<u8> = (0..len).map(|i| (x >> (i % 56)) as u8).collect();
            let _ = final_ftp_code(&buf);
        }
    }

    #[test]
    fn ftp_multiline_reply_uses_final_code() {
        assert_eq!(final_ftp_code(b"220-banner line\r\n220-more\r\n"), None);
        assert_eq!(final_ftp_code(b"220-banner\r\n220 ready\r\n"), Some(220));
        assert_eq!(final_ftp_code(b"530 Login incorrect\r\n"), Some(530));
        assert_eq!(final_ftp_code(b"331 password please\r\n"), Some(331));
    }
}
