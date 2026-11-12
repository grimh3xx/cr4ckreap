# brutereap

Bruteforce de login **multi-protocolo** para pentest autorizado — o irmão
"online" do [credreap](https://github.com/grimh3xx/credreap). Engine concorrente
com um protocolo por módulo.

> ⚠️ **Uso autorizado apenas.** Spray/bruteforce contra serviços sem permissão
> é crime. Cuidado com lockout de conta.

## Protocolos
| protocolo | estado |
|-----------|--------|
| `ftp`        | ✅ funcional (USER/PASS, códigos 230/530) |
| `http-basic` | ✅ funcional (Authorization: Basic, 401/403 = negado) |
| `ssh`        | 🚧 planejado (via `russh`) |

## Uso
```sh
brutereap ftp 10.0.0.5 -u admin -P rockyou.txt --stop-on-success
brutereap http-basic alvo.com -U users.txt -P pass.txt --path /admin -c 32
```
Combina listas (`-U`/`-P`) ou valores únicos (`-u`/`-p`). Sucessos vão pro
stdout com `[+] VÁLIDO user:pass`.

## Roadmap
- SSH (`russh`), SMB e RDP (reaproveitando `rdpeek`).
- Jitter/throttle por host pra evitar lockout.

## Build
```sh
cargo build --release
```
