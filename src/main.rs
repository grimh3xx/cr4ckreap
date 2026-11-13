use cr4ckreap::proto::{self, Proto};

use anyhow::{Context, Result};
use clap::Parser;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

/// cr4ckreap — multi-protocol login bruteforce (authorised use only).
#[derive(Parser)]
#[command(name = "cr4ckreap", version, about)]
struct Cli {
    /// Target protocol.
    #[arg(value_enum)]
    proto: Proto,

    /// Target host.
    target: String,

    /// Single username.
    #[arg(short = 'u', long, group = "userspec")]
    user: Option<String>,
    /// Username file (one per line).
    #[arg(short = 'U', long, group = "userspec")]
    userlist: Option<String>,

    /// Single password.
    #[arg(short = 'p', long, group = "passspec")]
    pass: Option<String>,
    /// Password file (one per line).
    #[arg(short = 'P', long, group = "passspec")]
    passlist: Option<String>,

    /// Port (defaults per protocol).
    #[arg(long)]
    port: Option<u16>,

    /// HTTP path (http-basic only).
    #[arg(long, default_value = "/")]
    path: String,

    /// Concurrency.
    #[arg(short, long, default_value_t = 16)]
    concurrency: usize,

    /// Per-attempt timeout (ms).
    #[arg(long, default_value_t = 5000)]
    timeout: u64,

    /// Stop at the first success.
    #[arg(long)]
    stop_on_success: bool,
}

fn load(single: Option<String>, list: Option<String>, what: &str) -> Result<Vec<String>> {
    if let Some(s) = single {
        return Ok(vec![s]);
    }
    if let Some(path) = list {
        let data =
            std::fs::read_to_string(&path).with_context(|| format!("reading {what}: {path}"))?;
        return Ok(data
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect());
    }
    Ok(Vec::new())
}

fn default_port(p: Proto) -> u16 {
    match p {
        Proto::Ftp => 21,
        Proto::HttpBasic => 80,
        Proto::Ssh => 22,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let users = load(cli.user.clone(), cli.userlist.clone(), "usernames")?;
    let passes = load(cli.pass.clone(), cli.passlist.clone(), "passwords")?;
    if users.is_empty() {
        anyhow::bail!("provide -u or -U");
    }
    if passes.is_empty() {
        anyhow::bail!("provide -p or -P");
    }
    let port = cli.port.unwrap_or_else(|| default_port(cli.proto));
    let to = Duration::from_millis(cli.timeout);
    let total = users.len() * passes.len();
    eprintln!(
        "[*] cr4ckreap: {:?} {}:{} — {} combinations, c={}",
        cli.proto, cli.target, port, total, cli.concurrency
    );

    let sem = Arc::new(Semaphore::new(cli.concurrency));
    let found = Arc::new(AtomicBool::new(false));
    let host = Arc::new(cli.target);
    let path = Arc::new(cli.path);
    let mut handles = Vec::new();

    for u in &users {
        for p in &passes {
            if cli.stop_on_success && found.load(Ordering::Relaxed) {
                break;
            }
            let (u, p) = (u.clone(), p.clone());
            let (host, path) = (host.clone(), path.clone());
            let (sem, found) = (sem.clone(), found.clone());
            let proto = cli.proto;
            handles.push(tokio::spawn(async move {
                let _permit = sem.acquire().await.ok()?;
                if cli.stop_on_success && found.load(Ordering::Relaxed) {
                    return None;
                }
                let res = match proto {
                    Proto::Ftp => proto::ftp(&host, port, &u, &p, to).await,
                    Proto::HttpBasic => proto::http_basic(&host, port, &path, &u, &p, to).await,
                    Proto::Ssh => proto::ssh(&host, port, &u, &p, to).await,
                };
                match res {
                    Ok(true) => {
                        found.store(true, Ordering::Relaxed);
                        println!("[+] VALID  {u}:{p}");
                        Some((u, p))
                    }
                    Ok(false) => None,
                    Err(_e) => None,
                }
            }));
        }
    }

    let mut hits = Vec::new();
    for h in handles {
        if let Ok(Some(hit)) = h.await {
            hits.push(hit);
        }
    }
    eprintln!("[*] done: {} valid credential(s)", hits.len());
    Ok(())
}
