# nexus-terminal# NEXUS Terminal 🔍

Un terminale avanzato per **analisi forense**, **cybersecurity** e uso quotidiano, scritto interamente in **C++17**.

```
  ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗
  ████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝
  ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗
  ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║
  ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║
  ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝
```

---

## Installazione

### Requisiti
- **macOS** o **Linux**
- `g++` con supporto C++17

### Compilazione
```bash
git clone https://github.com/assistenzacomunitas-cell/nexus-terminal.git
cd nexus-terminal
g++ -std=c++17 -O2 -o nxt nexus_all.cpp
```

### Installazione globale (comando `nxt` da ovunque)
```bash
sudo cp nxt /usr/local/bin/nxt
```

---

## Comandi disponibili

### 🔍 Analisi File & Binari
| Comando | Descrizione |
|---|---|
| `hash <file>` | Calcola MD5 e SHA-256 |
| `fileinfo <file>` | Metadati, permessi, timestamp |
| `hexdump <file>` | Dump esadecimale colorato |
| `strings <file>` | Estrai stringhe ASCII |
| `entropy <file>` | Analisi entropia (rileva file cifrati) |
| `binwalk <file>` | Cerca firme embedded |
| `magic <file>` | Identifica tipo tramite magic bytes |
| `exif <file>` | Estrai metadati EXIF |
| `checksum <file>` | CRC32 + Adler32 + MD5 + SHA256 |

### 🌐 Rete & Ricognizione
| Comando | Descrizione |
|---|---|
| `dns <host>` | DNS lookup + reverse |
| `dnsall <dominio>` | Tutti i record DNS |
| `whois <dominio>` | WHOIS lookup |
| `ping <host>` | ICMP ping |
| `traceroute <host>` | Traccia percorso di rete |
| `portscan <host> <start> <end>` | Scansione porte |
| `secheaders <host>` | Analisi security headers HTTP |

### 🔐 Crypto & Encoding
| Comando | Descrizione |
|---|---|
| `decode base64 <str>` | Decodifica Base64 |
| `encode hex <str>` | Encoding esadecimale |
| `hashid <hash>` | Identifica tipo hash |
| `hashcrack <hash> --common` | Crack hash vs password comuni |
| `cipher caesar <n> <testo>` | Cifrario Caesar |
| `cipher brute <testo>` | Brute-force ROT1-25 |
| `cipher vigenere <key> <testo>` | Cifrario Vigenere |
| `cipher morse <testo>` | Encode/decode Morse |
| `xor brute <file>` | XOR brute-force |
| `freq <file>` | Analisi frequenza lettere |
| `randgen uuid` | Genera UUID casuale |
| `passcheck <password>` | Analisi robustezza password |

### 🖥️ Sistema
| Comando | Descrizione |
|---|---|
| `sysaudit` | Audit sicurezza sistema |
| `processes` | Lista processi |
| `openports` | Porte in ascolto |
| `permcheck <dir>` | Trova file SUID/SGID |
| `filehide <dir>` | Trova file nascosti |
| `monitor` | Dashboard live CPU/RAM/rete |
| `myip` | IP pubblico e privato |

### 📦 NEX — Package Manager
```bash
nex install nmap       # Installa tool
nex search recon       # Cerca tool per categoria
nex list               # Tool installati
nex doctor             # Diagnostica ambiente
nex registry           # 47 tool disponibili
```

### 🗂 Git
Tutti i comandi git sono supportati nativamente:
```bash
git status
git add .
git commit -m "msg"
git push
```

### 🐚 Shell
`ls`, `cd`, `cat`, `mkdir`, `rm`, `mv`, `cp`, `find`, `grep`, `python3`, `pip`, `echo`, `env`, `chmod`, `df`, `ps` e molti altri.

---

## ⚠️ Disclaimer

Questo tool è destinato esclusivamente a scopi **educativi** e di **analisi forense autorizzata**.  
L'uso non autorizzato su sistemi altrui è illegale. Usa i comandi in modo responsabile e legale.

---

## Licenza

MIT License — libero per uso personale ed educativo.
