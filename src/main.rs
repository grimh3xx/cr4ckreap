mod proto;

use anyhow::{Context, Result};
use clap::Parser;
use proto::Proto;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

/// cr4ckreap — bruteforce de login multi-protocolo (uso autorizado apenas).
#[derive(Parser)]
#[command(name = "cr4ckreap", version, about)]
struct Cli {
    /// Protocolo alvo.
    #[arg(value_enum)]
    proto: Proto,

    /// Host alvo.
    target: String,

    /// Usuário único.
    #[arg(short = 'u', long, group = "userspec")]
    user: Option<String>,
    /// Arquivo de usuários (um por linha).
    #[arg(short = 'U', long, group = "userspec")]
    userlist: Option<String>,

    /// Senha única.
    #[arg(short = 'p', long, group = "passspec")]
    pass: Option<String>,
    /// Arquivo de senhas (um por linha).
    #[arg(short = 'P', long, group = "passspec")]
    passlist: Option<String>,

    /// Porta (padrão por protocolo).
    #[arg(long)]
    port: Option<u16>,

    /// Caminho HTTP (só http-basic).
    #[arg(long, default_value = "/")]
    path: String,

    /// Concorrência.
    #[arg(short, long, default_value_t = 16)]
    concurrency: usize,

    /// Timeout por tentativa (ms).
    #[arg(long, default_value_t = 5000)]
    timeout: u64,

    /// Para no primeiro sucesso.
    #[arg(long)]
    stop_on_success: bool,
}

fn load(single: Option<String>, list: Option<String>, what: &str) -> Result<Vec<String>> {
    if let Some(s) = single {
        return Ok(vec![s]);
    }
    if let Some(path) = list {
        let data = std::fs::read_to_string(&path).with_context(|| format!("lendo {what}: {path}"))?;
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
    let users = load(cli.user.clone(), cli.userlist.clone(), "usuários")?;
    let passes = load(cli.pass.clone(), cli.passlist.clone(), "senhas")?;
    if users.is_empty() {
        anyhow::bail!("informe -u ou -U");
    }
    if passes.is_empty() {
        anyhow::bail!("informe -p ou -P");
    }
    let port = cli.port.unwrap_or_else(|| default_port(cli.proto));
    let to = Duration::from_millis(cli.timeout);
    let total = users.len() * passes.len();
    eprintln!(
        "[*] cr4ckreap: {:?} {}:{} — {} combinações, c={}",
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
                        println!("[+] VÁLIDO  {u}:{p}");
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
    eprintln!("[*] concluído: {} credencial(is) válida(s)", hits.len());
    Ok(())
}
