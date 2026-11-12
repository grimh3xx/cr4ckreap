//! Tentativas de login por protocolo. Cada fn devolve Ok(true) em sucesso.
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
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

async fn read_code(s: &mut TcpStream, to: Duration) -> Result<u16> {
    let mut buf = [0u8; 512];
    let n = timeout(to, s.read(&mut buf)).await??;
    let line = String::from_utf8_lossy(&buf[..n]);
    let code: u16 = line.get(0..3).and_then(|c| c.parse().ok()).unwrap_or(0);
    Ok(code)
}

pub async fn ftp(host: &str, port: u16, user: &str, pass: &str, to: Duration) -> Result<bool> {
    let mut s = timeout(to, TcpStream::connect((host, port))).await??;
    let greet = read_code(&mut s, to).await?;
    if greet != 220 {
        return Err(anyhow!("greeting inesperado: {greet}"));
    }
    s.write_all(format!("USER {user}\r\n").as_bytes()).await?;
    let c1 = read_code(&mut s, to).await?;
    if c1 == 230 {
        return Ok(true); // sem senha
    }
    s.write_all(format!("PASS {pass}\r\n").as_bytes()).await?;
    let c2 = read_code(&mut s, to).await?;
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
    let mut buf = [0u8; 256];
    let n = timeout(to, s.read(&mut buf)).await??;
    let status = String::from_utf8_lossy(&buf[..n]);
    let code: u16 = status
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    // 401/403 = negado; 2xx/3xx = aceito
    Ok(code != 401 && code != 403 && code != 0)
}

pub async fn ssh(_host: &str, _port: u16, _user: &str, _pass: &str, _to: Duration) -> Result<bool> {
    // TODO: integrar russh (userauth password). Stub consciente para não
    // mascarar como falha de credencial.
    Err(anyhow!("SSH ainda não implementado (planejado via russh)"))
}
