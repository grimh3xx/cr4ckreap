# cr4ckreap

[![build](https://img.shields.io/github/actions/workflow/status/grimh3xx/cr4ckreap/build.yml?branch=main&style=flat-square&labelColor=111826&label=build)](https://github.com/grimh3xx/cr4ckreap/actions)
[![license](https://img.shields.io/github/license/grimh3xx/cr4ckreap?style=flat-square&labelColor=111826&color=22D3EE)](LICENSE)
![Rust](https://img.shields.io/badge/Rust-2021-3B82F6?style=flat-square&labelColor=111826)
![platform](https://img.shields.io/badge/Linux%20%7C%20Windows-22D3EE?style=flat-square&labelColor=111826)
![authorised use](https://img.shields.io/badge/authorised%20use-only-F87171?style=flat-square&labelColor=111826)


**Bruteforce de login multi-protocolo em Rust** para pentest autorizado — o irmão
"online" do [credreap](https://github.com/grimh3xx/credreap). Engine concorrente
com um protocolo por módulo e parada opcional no primeiro acerto.

<p align="center"><img src="docs/demo.svg" alt="cr4ckreap demo" width="100%"></p>

> ## ⚠️ Uso autorizado apenas
> Bruteforce/spray contra serviços sem permissão é crime e pode travar contas.
> Rode **somente** com escopo e autorização. A responsabilidade é sua.

## Protocolos

| protocolo | estado |
|---|---|
| `ftp`        | ✅ funcional (USER/PASS, códigos 230/530) |
| `http-basic` | ✅ funcional (Authorization: Basic, 401/403 = negado) |
| `ssh`        | 🚧 planejado (via `russh`) |

## Uso

```sh
cr4ckreap ftp 10.0.0.5 -u admin -P rockyou.txt --stop-on-success
cr4ckreap http-basic alvo.com -U users.txt -P pass.txt --path /admin -c 32
```

Combina listas (`-U`/`-P`) ou valores únicos (`-u`/`-p`). Sucessos saem com
`[+] VÁLIDO user:pass`.

## Roadmap

- SSH (`russh`), SMB e RDP (reaproveitando o [rdpr0wl](https://github.com/grimh3xx/rdpr0wl)).
- Jitter/throttle por host pra evitar lockout.

## Build

```sh
cargo build --release
```

## Licença

MIT. Veja [LICENSE](LICENSE).
