# 🛡️ SystemAuditor Enterprise

> **Distributed OS Security Compliance, CIS Benchmarking & Zero-Trust Telemetry Engine**  
> Audyt zgodności stacji roboczych i serwerów (Windows & Linux) ze standardami **CIS Benchmarks L1/L2**, **Dyrektywą NIS2 (Art. 21)**, **ISO/IEC 27001:2022** oraz **KSC/KRI**.

---

## 🚀 Główne Funkcjonalności

1. **Głębokie Skanowanie OS (22 Natywne Reguły Bezpieczeństwa)**:
   - **Windows**: SMBv1, UAC EnableLUA, Długość hasła (Win32 API NetUserModalsGet), Windows Defender Firewall, WDigest cleartext credentials, NTLMv2 Level 5, LSASS RunAsPPL, PowerShell Script Block Logging, Blokada konta Gościa, RDP NLA, UEFI Secure Boot, Audyt niebezpiecznych portów (Telnet/FTP/TFTP/RSH).
   - **Linux**: SSH PermitRootLogin, IPv4 ip_forward, ICMP redirects, uprawnienia `/etc/shadow`, ASLR (`randomize_va_space=2`), demon `auditd`, wykrywanie kont backdoor UID=0 w `/etc/passwd`, sudoers `NOPASSWD`, uprawnienia `/boot/grub/grub.cfg`, audyt portów w `/proc/net/tcp`.
   - **Brak RCE**: Wszystkie pomiary zbierane są w sposób deklaratywny i bezpieczny (`shell=False`, bezpośredni odczyt WinReg, Win32 API, `/proc`, `/sys`).

2. **Kryptograficzny Zero-Trust Transport**:
   - Certyfikaty tożsamości mTLS 1.3 (ECDSA P-256) per endpoint.
   - Wbudowane wewnętrzne PKI (`pki_manager.py`) z certyfikatami CA i CRL.
   - Podpis HMAC-SHA256 i nagłówki Anti-Replay (`X-Request-Timestamp`, `X-Request-Nonce`).

3. **Detekcja Zatruwania Bazy (Anti-Poisoning & All-Green Lie)**:
   - Wykrywanie manipulacji tożsamością agenta (X.509 CN vs deklarowany `agent_id`).
   - Wykrywanie syntetycznych raportów o zerowej entropii czasowej.
   - Wykrywanie fałszywych raportów 100% zgodności bez restartu OS (All-Green Lie).

4. **Auto-Remediacja (1-Click Remediation & Rollback)**:
   - Generowanie skryptów naprawczych **PowerShell (`.ps1`)**, **Bash (`.sh`)** oraz playbooków **Ansible (`.yml`)** dopasowanych do wyników `FAIL`.
   - Automatyczny backup stanu początkowego oraz obsługa flag `-DryRun` i `-Rollback`.

5. **Historia Zmian & Dryft Konfiguracji (Diff Viewer)**:
   - Śledzenie zmian postury bezpieczeństwa w czasie.
   - Porównanie dwóch skanów z wyróżnieniem regresji (`PASS → FAIL`) oraz napraw (`FAIL → PASS`).

6. **Raporty Audytowe PDF / Drukuj**:
   - Raport CISO Executive Summary z matrycą zgodności z **NIS2**, **ISO 27001**, **KSC** i **CIS**.

7. **Alerty SOC & Integracje (Webhooks / SIEM)**:
   - Integracja z **Slack**, **Microsoft Teams**, **Discord** i kolektorami **SIEM (Splunk / QRadar)**.

8. **Zero-Trust IAM & MFA (TOTP RFC 6238)**:
   - PBKDF2-HMAC-SHA256, 2FA/MFA z kodami czasowymi TOTP, wymóg utwardzenia fabrycznego konta przy pierwszym logowaniu.

---

## 📂 Struktura Projektu

```
SystemAuditor/
├── agent_poc.py               # Zero-dependency Agent dla Windows i Linux (Python stdlib)
├── agent_dotnet/              # Opcjonalny natywny Agent C# .NET 8
│   └── SystemAuditorAgent.cs
├── backend/
│   ├── database.py            # Warstwa SQLite WAL + schemat PostgreSQL/TimescaleDB
│   ├── main.py                # Serwer centralny FastAPI, WebSockets, IAM i API
│   ├── pki_manager.py         # Silnik Zero-Trust PKI (ECDSA X.509 CA)
│   ├── rule_engine.py         # Silnik ewaluacji reguł CIS i detektor Anti-Poisoning
│   └── schema_timescaledb.sql # Produkcyjny DDL dla bazy TimescaleDB
├── frontend/
│   └── index.html             # Responsywny panel webowy (Tailwind CSS, Vanilla JS)
├── rules_catalog.yaml         # Podpisany deklaratywny katalog reguł CIS
├── run_system.py              # Główny skrypt uruchomieniowy i autoverification
├── test_e2e.py                # Testy integracyjne End-to-End
├── docker-compose.yml         # Konfiguracja konteneryzacji Docker
└── README.md
```

---

## ⚡ Szybki Start

### 1. Wymagania
- Python 3.10+
- System Windows 10/11 / Windows Server lub Linux (Debian/Ubuntu/RHEL)

### 2. Instalacja zależności serwera
```bash
pip install fastapi uvicorn cryptography pyyaml
```

### 3. Uruchomienie Serwera i Panelu
```bash
python run_system.py
```
Panel dostępny jest pod adresem:
- `http://localhost:8000`

### 4. Uruchomienie Agenta na stacji roboczej / serwerze
Agent nie wymaga instalacji żadnych dodatkowych pakietów (`pip`), działa na czystej bibliotece standardowej Pythona:
```bash
# Skan jednorazowy
python agent_poc.py --server http://localhost:8000

# Praca jako demon w tle (co 5 minut)
python agent_poc.py --server http://localhost:8000 --daemon --interval 300
```

---

## 🔒 Bezpieczeństwo i Licencja
Projekt przeznaczony do audytowania zgodności i utwardzania środowisk enterprise zgodnie z CIS Benchmarks.
Wszelkie prawa zastrzeżone.
