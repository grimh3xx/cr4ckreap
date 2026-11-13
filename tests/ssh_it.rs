//! In-process SSH server to prove the password-auth client path end to end:
//! the correct credential authenticates, a wrong one does not.
use std::sync::Arc;
use std::time::Duration;

use russh::keys::{Algorithm, PrivateKey};
use russh::server::{Auth, Config, Handler, Server};
use tokio::net::TcpListener;

struct Srv;
struct Sess;

impl Server for Srv {
    type Handler = Sess;
    fn new_client(&mut self, _peer: Option<std::net::SocketAddr>) -> Sess {
        Sess
    }
}

impl Handler for Sess {
    type Error = russh::Error;
    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        if user == "alice" && password == "S3cr3t!" {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }
}

async fn spawn_server() -> u16 {
    let mut config = Config::default();
    config.auth_rejection_time = Duration::from_millis(50);
    config.inactivity_timeout = Some(Duration::from_secs(5));
    config
        .keys
        .push(PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap());
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut srv = Srv;
        let _ = srv.run_on_socket(config, &listener).await;
    });
    port
}

#[tokio::test]
async fn correct_password_authenticates() {
    let port = spawn_server().await;
    let to = Duration::from_secs(5);
    let ok = cr4ckreap::proto::ssh("127.0.0.1", port, "alice", "S3cr3t!", to)
        .await
        .expect("ssh attempt should complete");
    assert!(ok, "valid credential must authenticate");
}

#[tokio::test]
async fn wrong_password_is_rejected() {
    let port = spawn_server().await;
    let to = Duration::from_secs(5);
    let ok = cr4ckreap::proto::ssh("127.0.0.1", port, "alice", "nope", to)
        .await
        .expect("ssh attempt should complete");
    assert!(!ok, "wrong credential must be rejected");
}
