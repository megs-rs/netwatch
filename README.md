# NetWatch

Analisador de tráfego de rede local via CLI. Foco: auditoria de dispositivos IoT (câmeras IP etc.) — quem o dispositivo conversa, que tipo de tráfego, e quanto.

## Instalação

```bash
pip install -e .
```

Requer Python 3.11+. Dependências: `click`, `scapy`.

## Comandos

```bash
netwatch --help
netwatch capture start -i wlp0s20f3 --duration 30s --db ./netwatch.db
netwatch capture status
netwatch capture stop
netwatch analyze offline capture.pcap --db ./netwatch.db
netwatch devices list --db ./netwatch.db
netwatch devices rename AA:BB:CC:DD:EE:FF "Câmera Sala"
netwatch devices tag AA:BB:CC:DD:EE:FF iot
netwatch flows list --device AA:BB:CC:DD:EE:FF --format json
netwatch summary --since 7d
netwatch export -o export.csv --format csv
netwatch config
```

### Formato de saída

`--format table|json|csv` disponível em `devices list`, `flows list`, `summary` e `export`.

### Filtros temporais

`--since 24h`, `--since 7d`, `--since 30d` — aceita `Nd`, `Nh`, `Nm` ou número inteiro (dias).

### Captura ao vivo

`capture start` captura de uma interface e ingere direto no DB:

```bash
netwatch capture start -i eth0 --duration 30s        # para após 30s
netwatch capture start -i eth0                       # contínuo; Ctrl+C para parar
netwatch capture status                              # estado da captura ativa
netwatch capture stop                                # encerra captura
```

`--duration` aceita `10`, `30s`, `5m`, `1h` ou `continuous`. Para captura contínua com `stop`/`status` de outro processo, rode `capture start` em background.

Requer `root`/`CAP_NET_RAW` para capturar. Alternativa sem privilégio: capture com `tcpdump` e use `analyze offline`.

## Arquitetura

```
netwatch/
├── cli.py              # Click entry, todos os comandos
├── output.py           # format_output(): table/json/csv
├── capture/engine.py   # Scapy: read_packets(), iter_packets()
├── analyzer/
│   ├── flow.py         # Agregação bidirecional de flows (5-tuple)
│   ├── protocol.py     # Classificação L4 + DPI L7 (TLS, HTTP, SSH)
│   └── device.py       # Extração de MAC, hostname via DNS
├── enrichment/oui.py   # MAC → vendor (IEEE OUI)
└── storage/
    ├── db.py           # SQLite (WAL mode) + CRUD
    └── models.py       # Dataclasses: Device, Flow, DNSLog
```

## Banco de dados

- Camada padrão: `~/.netwatch/netwatch.db`
- Criado automaticamente na primeira execução (WAL + foreign keys ON)
- `--db <path>` em qualquer comando para usar outro path

## Enrichment OUI

Baixe a base de fabricantes (MAC → vendor) — formato `nmap-mac-prefixes` — e os comandos `analyze offline`/`capture start` resolvem vendors automaticamente:

```bash
netwatch update-oui                    # baixa para data/oui.txt
netwatch update-oui --output /tmp/o.txt # destino customizado
netwatch update-oui --url <URL>        # fonte alternativa
```

## Status

**v0.1 (MVP)** — Fase 2 concluída.

| Comando | Status |
|---|---|
| `capture start/stop/status` | Funcional |
| `analyze offline` | Funcional |
| `devices list/rename/tag` | Funcional |
| `flows list` | Funcional |
| `summary`, `export`, `config` | Funcional |
| `update-oui` | Funcional |

### Fora do escopo

- `alerts check`, `watch`
- Flags de enriquecimento (`--resolve-dns`, `--asn`)
- `--capture-payload`
- Captura em modo `mirror`/`gateway` (aceita as flags, mas trata igual a `live`)

## Licença

A definir.
