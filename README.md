<img src="docs/banner.svg" alt="cr4ckreap" width="100%">

[![build](https://img.shields.io/github/actions/workflow/status/grimh3xx/cr4ckreap/build.yml?branch=main&style=flat-square&labelColor=111826&label=build)](https://github.com/grimh3xx/cr4ckreap/actions)
[![license](https://img.shields.io/github/license/grimh3xx/cr4ckreap?style=flat-square&labelColor=111826&color=22D3EE)](LICENSE)
![Rust](https://img.shields.io/badge/Rust-2021-3B82F6?style=flat-square&labelColor=111826)
![platform](https://img.shields.io/badge/Linux%20%7C%20Windows-22D3EE?style=flat-square&labelColor=111826)
![authorised use](https://img.shields.io/badge/authorised%20use-only-F87171?style=flat-square&labelColor=111826)


**Multi-protocol login bruteforce in Rust** for authorised pentests — the online
twin of [credreap](https://github.com/grimh3xx/credreap). Concurrent engine with
one protocol per module and optional stop-on-first-hit.

<p align="center"><img src="docs/demo.svg" alt="cr4ckreap demo" width="100%"></p>

> ## ⚠️ Authorised use only
> Bruteforce/spray against services without permission is a crime and can lock
> accounts out. Run **only** with scope and authorisation. You are responsible.

## Protocols

| protocol | state |
|---|---|
| `ssh`        | ✅ working (russh password auth; covered by an in-process server test) |
| `ftp`        | ✅ working (USER/PASS, multi-line reply aware) |
| `http-basic` | ✅ working (Authorization: Basic, 401/403 = denied) |

## Usage

```sh
cr4ckreap ssh 10.0.0.5 -U users.txt -P rockyou.txt --stop-on-success
cr4ckreap ftp 10.0.0.5 -u admin -P rockyou.txt --stop-on-success
cr4ckreap http-basic site.com -U users.txt -P pass.txt --path /admin -c 32
```

Mix lists (`-U`/`-P`) or single values (`-u`/`-p`). Hits print as
`[+] VALID user:pass`.

## Tests

```sh
cargo test --release      # unit + in-process SSH server (accept & reject paths)
```

## Roadmap

- SMB and RDP (reusing [rdpr0wl](https://github.com/grimh3xx/rdpr0wl)).
- Per-host jitter/throttle to avoid lockout.

## Build

```sh
cargo build --release
```

## License

MIT. See [LICENSE](LICENSE).
