# Especificação Técnica — NetWatch CLI

## Analisador de Tráfego de Rede Local (dispositivos, destinos, protocolos e volume de dados)

**Versão do documento:** 1.0
**Tipo:** Especificação funcional e técnica para ferramenta de linha de comando (CLI)

---

## 1. Visão Geral

### 1.1 Objetivo

O NetWatch é uma ferramenta de linha de comando para captura passiva e análise de tráfego em uma rede local, com foco em responder três perguntas por dispositivo:

1. **Com quem esse dispositivo conversa?** (origem → destino: IPs, hostnames, domínios, geolocalização/ASN)
2. **Que tipo de tráfego é esse?** (protocolo de rede/transporte e, quando possível, aplicação: HTTP, HTTPS/TLS, DNS, RTSP, MQTT, etc.)
3. **Quanto tráfego é esse?** (bytes/pacotes enviados e recebidos, ao longo do tempo)

Caso de uso principal citado: auditar dispositivos IoT (ex.: câmeras IP) para identificar conexões para servidores desconhecidos/externos, volume de upload incomum, ou protocolos inesperados.

### 1.2 Não-objetivos (escopo excluído da v1)

- Não decodifica conteúdo de tráfego criptografado (HTTPS/TLS, RTSPS) — apenas metadados (SNI, IP, porta, volume).
- Não é uma ferramenta de ataque/interceptação ativa (sem ARP spoofing, sem MITM de certificados) na v1.
- Não substitui firewall/IDS; é uma ferramenta de **visibilidade e auditoria**.

### 1.3 Princípio de operação

Captura **passiva** de pacotes via porta espelhada (SPAN/mirror), interface em modo promíscuo, ou execução no próprio gateway/roteador. O software nunca injeta pacotes na rede (exceto resolução DNS reversa opcional, que é tráfego legítimo e configurável).

---

## 2. Requisitos Legais e Éticos (obrigatório constar)

- A ferramenta deve exibir, na primeira execução, um aviso de que a captura de tráfego de terceiros sem autorização pode violar legislação local (ex.: LGPD no Brasil, GDPR na UE) e exigir confirmação explícita (`--i-have-authorization` ou prompt interativo).
- Deve haver um modo de **anonimização** (`--anonymize`) que hasheia IPs de dispositivos internos em relatórios exportados, para uso em auditorias compartilhadas com terceiros.
- Não deve armazenar payload de aplicação por padrão — apenas metadados. Captura de payload deve ser opt-in explícito (`--capture-payload`) com aviso adicional.

---

## 3. Arquitetura

```
┌─────────────────┐     ┌──────────────────┐     ┌───────────────────┐
│  Captura         │────▶│  Pipeline de      │────▶│  Armazenamento     │
│  (libpcap/AF_PACKET) │  Processamento    │     │  (SQLite local)    │
└─────────────────┘     └──────────────────┘     └───────────────────┘
                                 │                          │
                                 ▼                          ▼
                        ┌──────────────────┐     ┌───────────────────┐
                        │  Identificação    │     │  Camada de         │
                        │  de dispositivos  │     │  Consulta/Relatório│
                        │  (MAC/OUI, DHCP,  │     │  (comandos CLI)    │
                        │  mDNS, hostname)  │     └───────────────────┘
                        └──────────────────┘
```

### 3.1 Componentes

| Componente | Responsabilidade |
|---|---|
| **Capture Engine** | Lê pacotes brutos da interface (via libpcap/npcap ou socket AF_PACKET). Suporta captura ao vivo ou leitura de arquivo `.pcap`/`.pcapng`. |
| **Flow Aggregator** | Agrupa pacotes em "fluxos" (5-tupla: IP origem, IP destino, porta origem, porta destino, protocolo). Contabiliza bytes/pacotes por fluxo, timestamps de início/fim. |
| **Protocol Classifier** | Identifica protocolo de aplicação por porta conhecida, DPI leve (assinaturas de payload, ex: handshake TLS) e SNI/hostname quando disponível. |
| **Device Identifier** | Associa MAC address a fabricante (tabela OUI/IEEE), nome via DHCP hostname, mDNS/Bonjour, NetBIOS, ou apelido definido manualmente pelo usuário. |
| **Storage Layer** | Persiste fluxos e metadados em SQLite (arquivo local), com rotação/retenção configurável. |
| **Query/Report Engine** | Camada que os subcomandos da CLI consultam para gerar saídas (tabelas, JSON, CSV, alertas). |
| **Enrichment (opcional)** | Resolução DNS reversa, lookup de ASN/geolocalização de IP, lookup de fabricante via IEEE OUI database (local, sem chamada externa por padrão). |

### 3.2 Modo de captura

| Modo | Descrição | Requisito |
|---|---|---|
| `live` | Captura direta de uma interface de rede | Permissão de root/CAP_NET_RAW ou modo promíscuo habilitado |
| `mirror` | Captura de porta espelhada de switch gerenciável | Interface dedicada conectada à porta SPAN |
| `gateway` | Executa no próprio roteador/gateway (ex: dentro de um container em OpenWrt) | Acesso root ao gateway |
| `offline` | Lê um arquivo `.pcap`/`.pcapng` pré-capturado (ex: exportado do Wireshark) | Nenhum, apenas leitura de arquivo |

---

## 4. Modelo de Dados

### 4.1 Entidade: Device (Dispositivo)

| Campo | Tipo | Descrição |
|---|---|---|
| `mac_address` | string | Identificador primário do dispositivo na rede local |
| `vendor` | string | Fabricante identificado via OUI (ex: "Hikvision", "Dahua", "Intelbras") |
| `ip_addresses` | lista | IPs observados associados a esse MAC (histórico, pois DHCP pode mudar) |
| `hostname` | string \| null | Nome via DHCP/mDNS/NetBIOS, se disponível |
| `alias` | string \| null | Apelido definido manualmente pelo usuário (`netwatch device rename`) |
| `first_seen` | timestamp | Primeira vez observado na rede |
| `last_seen` | timestamp | Última atividade observada |
| `tags` | lista | Categorias definidas pelo usuário (ex: "camera", "iot", "trusted") |

### 4.2 Entidade: Flow (Fluxo)

| Campo | Tipo | Descrição |
|---|---|---|
| `flow_id` | uuid | Identificador único |
| `src_ip`, `dst_ip` | string | IPs de origem e destino |
| `src_mac`, `dst_mac` | string | MACs de origem/destino (quando ambos locais) ou MAC local + gateway |
| `src_port`, `dst_port` | int | Portas (quando TCP/UDP) |
| `l4_protocol` | enum | TCP, UDP, ICMP, outro |
| `l7_protocol` | string \| null | HTTP, TLS/HTTPS, DNS, RTSP, RTP, MQTT, SSH, NTP, etc. |
| `sni` / `dst_hostname` | string \| null | Nome do servidor de destino (via SNI de TLS ou resolução DNS) |
| `dst_asn` | string \| null | Organização/ASN do IP de destino (enriquecimento opcional) |
| `dst_country` | string \| null | País do IP de destino (enriquecimento opcional) |
| `bytes_sent` | int | Bytes do dispositivo local para o destino |
| `bytes_received` | int | Bytes do destino para o dispositivo local |
| `packets_sent` / `packets_received` | int | Contagem de pacotes |
| `started_at` / `last_activity_at` | timestamp | Janela temporal do fluxo |
| `direction` | enum | `internal-internal`, `internal-external` |

### 4.3 Entidade: DNS Log (opcional, se captura de DNS habilitada)

| Campo | Tipo | Descrição |
|---|---|---|
| `device_mac` | string | Dispositivo que fez a consulta |
| `query_name` | string | Domínio consultado |
| `resolved_ips` | lista | IPs retornados |
| `timestamp` | timestamp | Momento da consulta |

---

## 5. Especificação da CLI

### 5.1 Convenção geral

```
netwatch <comando> [subcomando] [opções]
```

Saída padrão em tabela formatada para humanos; toda saída deve suportar `--format json|csv|table` para integração com outras ferramentas (ex: `jq`, planilhas, scripts de alerta).

### 5.2 Comandos principais

#### `netwatch capture start`
Inicia captura em tempo real.

```
netwatch capture start \
  --interface eth0 \
  --mode mirror \
  --duration 24h \
  --resolve-dns \
  --resolve-asn \
  --db ./netwatch.db
```

| Flag | Descrição | Padrão |
|---|---|---|
| `--interface, -i` | Interface de rede a capturar | obrigatório |
| `--mode` | `live`, `mirror`, `gateway` | `live` |
| `--duration` | Tempo de captura (`1h`, `24h`, `continuous`) | `continuous` |
| `--filter` | Filtro BPF (sintaxe tcpdump) para restringir captura | vazio (tudo) |
| `--resolve-dns` | Habilita resolução DNS reversa passiva | `false` |
| `--resolve-asn` | Habilita lookup de ASN/organização do IP | `false` |
| `--capture-payload` | Armazena payload bruto (requer confirmação) | `false` |
| `--db` | Caminho do arquivo de banco de dados | `~/.netwatch/netwatch.db` |
| `--daemon, -d` | Roda em background como serviço | `false` |

#### `netwatch capture stop` / `netwatch capture status`
Para captura em execução ou mostra status/estatísticas da captura ativa (pacotes/seg, dispositivos ativos, uptime).

#### `netwatch analyze offline <arquivo.pcap>`
Processa um arquivo `.pcap`/`.pcapng` já existente (ex: exportado do Wireshark ou tcpdump) e popula o banco de dados, sem precisar de captura ao vivo.

```
netwatch analyze offline captura_camera.pcapng --db ./netwatch.db
```

#### `netwatch devices list`
Lista dispositivos identificados na rede.

```
netwatch devices list --tag camera --sort bytes_total --format table
```

| Flag | Descrição |
|---|---|
| `--tag` | Filtra por tag |
| `--since` | Filtra por atividade desde um período (`24h`, `7d`) |
| `--sort` | `bytes_total`, `last_seen`, `flow_count` |

Saída exemplo:
```
MAC                VENDOR       IP              ALIAS         FLOWS  BYTES(TOTAL)  LAST SEEN
a4:14:37:xx:xx:xx   Hikvision    192.168.1.45    cam-garagem   142    1.2 GB        2m ago
b0:52:16:xx:xx:xx   Dahua        192.168.1.52    cam-entrada   98     340 MB        5m ago
```

#### `netwatch devices rename <mac> <alias>`
Define apelido legível para um dispositivo.

#### `netwatch devices tag <mac> <tag>`
Associa categoria/tag a um dispositivo.

#### `netwatch flows list`
Lista fluxos de rede com filtros.

```
netwatch flows list --device cam-garagem --external-only --since 24h --format json
```

| Flag | Descrição |
|---|---|
| `--device` | Filtra por MAC ou alias |
| `--protocol` | Filtra por protocolo L4 ou L7 (`tcp`, `tls`, `dns`, `rtsp`) |
| `--external-only` | Mostra apenas tráfego que sai da rede local |
| `--internal-only` | Mostra apenas tráfego entre dispositivos locais |
| `--dst-country` | Filtra por país de destino (requer `--resolve-asn` na captura) |
| `--min-bytes` | Filtra fluxos acima de um volume mínimo |
| `--since` / `--until` | Janela temporal |

Saída exemplo:
```
DEVICE        DESTINO                  PORTA  PROTOCOLO  SNI/HOST              BYTES↑    BYTES↓    PAÍS
cam-garagem   47.90.xx.xx              443    TLS        xxx.hikvision.com     45 KB     2.1 MB    CN
cam-garagem   192.168.1.1              53     DNS        -                     1 KB      2 KB      Local
```

#### `netwatch summary`
Visão consolidada (dashboard textual) — dispositivo × destino × volume no período.

```
netwatch summary --since 7d --group-by device,dst_country
```

Saída exemplo:
```
RESUMO DE TRÁFEGO — últimos 7 dias

Dispositivo: cam-garagem (Hikvision)
  Total: 8.4 GB (↑ 8.1 GB / ↓ 300 MB)
  Destinos externos: 3 servidores únicos
    - 47.90.xx.xx (CN, Alibaba Cloud)     7.9 GB   ⚠ maior consumidor
    - 8.8.8.8 (US, Google DNS)            2 MB
  Destinos internos: 1 (NVR local, 192.168.1.10)
```

#### `netwatch alerts`
Verifica regras de alerta configuradas contra os dados capturados.

```
netwatch alerts check --rules ./rules.yaml
```

Exemplos de regras suportadas (arquivo YAML de configuração):
```yaml
rules:
  - name: "Câmera enviando dados para fora do Brasil"
    condition: "device.tag == 'camera' AND flow.dst_country != 'BR' AND flow.direction == 'internal-external'"
    severity: warning

  - name: "Volume de upload incomum"
    condition: "device.tag == 'camera' AND flow.bytes_sent > 500MB AND window == '1h'"
    severity: critical

  - name: "Novo destino nunca visto antes"
    condition: "flow.dst_ip NOT IN device.known_destinations"
    severity: info
```

#### `netwatch export`
Exporta dados para análise externa.

```
netwatch export --format csv --output relatorio.csv --since 30d
netwatch export --format json --anonymize --output auditoria.json
```

#### `netwatch watch`
Modo interativo "live" no terminal (estilo `top`/`iftop`), atualizando em tempo real: top dispositivos por banda, top destinos, protocolos em uso.

```
netwatch watch --interface eth0 --refresh 2s
```

#### `netwatch config`
Gerencia configuração persistente (interface padrão, banco de dados padrão, chaves de enriquecimento opcional como base de ASN).

---

## 6. Identificação de Dispositivos (câmeras e IoT em geral)

1. **MAC → Fabricante:** consulta a tabela OUI (IEEE) local (arquivo `oui.txt` embutido/atualizável), permitindo identificar marcas de câmeras (Hikvision, Dahua, Intelbras, Axis, etc.) mesmo sem hostname.
2. **DHCP snooping passivo:** se a captura observar pacotes DHCP, extrai o hostname anunciado pelo dispositivo (muitas câmeras se identificam no DHCP request).
3. **mDNS/SSDP/UPnP:** câmeras e dispositivos IoT costumam anunciar serviços via mDNS (porta 5353) ou SSDP (porta 1900), o que revela nome de serviço, modelo, às vezes até firmware.
4. **Fingerprint de portas/protocolo:** presença de RTSP (554), ONVIF (porta 80/8000 com payload característico), ou streams RTP é um forte indicador de câmera IP.
5. **Classificação manual:** usuário pode confirmar/corrigir via `netwatch devices tag`.

---

## 7. Classificação de Protocolos

| Camada | Método |
|---|---|
| L4 | Direto do cabeçalho IP (TCP/UDP/ICMP) |
| L7 (portas conhecidas) | Tabela de mapeamento porta→protocolo (80=HTTP, 443=TLS, 53=DNS, 554=RTSP, 1883=MQTT, 8000/8080=ONVIF comum) |
| L7 (DPI leve) | Assinatura de bytes iniciais do payload (ex: handshake TLS `0x16 0x03`, banner SSH) — não decodifica conteúdo, só identifica o protocolo |
| L7 (SNI) | Em handshakes TLS, extrai o campo SNI (Server Name Indication) não criptografado, revelando o hostname de destino mesmo sem decriptar o tráfego |

---

## 8. Requisitos Não-Funcionais

| Requisito | Especificação |
|---|---|
| **Performance** | Deve suportar captura em redes até 1 Gbps sem perda significativa de pacotes em hardware modesto (ex: Raspberry Pi 4) |
| **Armazenamento** | Retenção configurável (`--retention 30d`); rotação automática do banco SQLite; opção de exportar e limpar |
| **Portabilidade** | Linux como plataforma primária (via libpcap/AF_PACKET); suporte opcional a Windows (via Npcap) e macOS |
| **Privacidade** | Nenhuma chamada de rede externa por padrão (enriquecimento de ASN/geo deve usar base de dados local, ex: MaxMind GeoLite2, não API externa, a menos que o usuário habilite explicitamente) |
| **Permissões** | Deve verificar e informar claramente a necessidade de `CAP_NET_RAW`/root antes de tentar captura |
| **Extensibilidade** | Arquitetura em módulos permite adicionar novos classificadores de protocolo ou exportadores sem alterar o core |
| **Observabilidade** | Logs estruturados (`--log-level`), métricas de captura (pacotes processados, perdidos, taxa) |

---

## 9. Stack Técnica Sugerida

| Camada | Opção recomendada | Alternativa |
|---|---|---|
| Linguagem | Go (binário único, performance nativa, boas libs de rede) | Python (mais rápido de prototipar, usar Scapy/PyShark) |
| Captura de pacotes | `gopacket` + `libpcap` (Go) | `Scapy` ou `pyshark` (Python, usa tshark por baixo) |
| Banco de dados | SQLite (arquivo único, zero configuração) | DuckDB (melhor para consultas analíticas em volume maior) |
| CLI framework | `cobra` (Go) | `Click` ou `Typer` (Python) |
| Base OUI | Arquivo local `oui.txt` (IEEE, atualizável via `netwatch update-oui`) | — |
| Base Geo/ASN (opcional) | MaxMind GeoLite2 (arquivo local, licença gratuita) | ip-api local cache |

*Recomendação: Go é preferível se o objetivo é rodar continuamente em um dispositivo embarcado (Raspberry Pi, roteador) por menor consumo de recursos e distribuição como binário único sem dependências.*

---

## 10. Fluxo de Uso Típico (exemplo prático)

```bash
# 1. Instalar e configurar
netwatch config set --interface eth0 --db ~/.netwatch/casa.db

# 2. Ligar a porta espelhada do switch nesse eth0, então iniciar captura contínua
netwatch capture start --mode mirror --resolve-dns --resolve-asn --daemon

# 3. Depois de algumas horas, listar dispositivos descobertos
netwatch devices list

# 4. Identificar e nomear a câmera
netwatch devices rename a4:14:37:xx:xx:xx cam-garagem
netwatch devices tag cam-garagem camera

# 5. Ver para onde ela está mandando dados
netwatch flows list --device cam-garagem --external-only --since 24h

# 6. Configurar alerta para tráfego suspeito
netwatch alerts check --rules ./rules.yaml

# 7. Gerar relatório para arquivar/compartilhar
netwatch export --format csv --output auditoria_cameras.csv --since 30d
```

---

## 11. Roadmap (fora do escopo da v1, mas previsto na arquitetura)

- v1.1: Interface web opcional consumindo o mesmo banco SQLite (somente leitura).
- v1.2: Suporte a NetFlow/sFlow como fonte alternativa de dados (sem precisar de porta espelhada).
- v1.3: Bloqueio ativo opcional via integração com firewall (nftables/iptables) para destinos marcados como maliciosos — módulo separado, com confirmação explícita do usuário.
- v2.0: Correlação com feeds de threat intelligence (listas de IPs maliciosos conhecidos), mantendo consultas locais/offline sempre que possível.

---

## 12. Resumo de Comandos (referência rápida)

```
netwatch capture start        Inicia captura ao vivo
netwatch capture stop         Para captura
netwatch capture status       Status da captura ativa
netwatch analyze offline      Processa arquivo .pcap existente
netwatch devices list         Lista dispositivos
netwatch devices rename       Define apelido
netwatch devices tag          Categoriza dispositivo
netwatch flows list           Lista fluxos de tráfego
netwatch summary              Resumo consolidado por período
netwatch alerts check         Verifica regras de alerta
netwatch export               Exporta dados (csv/json)
netwatch watch                Modo ao vivo interativo (estilo top)
netwatch config                Gerencia configuração
netwatch update-oui            Atualiza base de fabricantes (MAC)
```
