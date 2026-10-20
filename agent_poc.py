"""
SystemAuditor Enterprise — Kompletny Moduł Agenta Endpoint (Windows & Linux)
============================================================================
Realizuje:
1. Natywny odczyt parametrów bezpieczeństwa OS bez wywoływania powłoki (shell=False, brak RCE):
   - Windows (8 reguł CIS): SMBv1, UAC (EnableLUA), MinimumPasswordLength (NetUserModalsGet Win32 API),
     Windows Defender Firewall, WDigest Cleartext Credentials, LAN Manager Auth Level (NTLMv2),
     LSASS Protected Process Light (RunAsPPL), PowerShell Script Block Logging.
   - Linux (6 reguł CIS): SSH PermitRootLogin, IPv4 ip_forward, ICMP accept_redirects,
     /etc/shadow permissions & UID/GID, Kernel ASLR (randomize_va_space), auditd systemd status.
2. Weryfikację podpisu kryptograficznego Ed25519 pobranego katalogu reguł.
3. Generowanie klucza prywatnego ECDSA P-256 i żądania CSR (PKCS#10) do rejestracji mTLS.
4. Bezpieczną wysyłkę raportu JSON przez mTLS / HTTPS z podpisem integralności HMAC-SHA256
   oraz nagłówkami ochrony Anti-Replay (`X-Request-Timestamp`, `X-Request-Nonce`).
"""

import argparse
import ctypes
import datetime
import hashlib
import hmac
import json
import logging
import os
import platform
import re
import socket
import subprocess
import sys
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional
import urllib.error
import urllib.request

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("SystemAuditorAgent")


# =====================================================================
# MODELE DANYCH
# =====================================================================

@dataclass
class AuditMeasurement:
    """Reprezentacja pojedynczego pomiaru parametru bezpieczeństwa z systemu OS."""
    check_id: str
    category: str
    title: str
    collector_type: str
    target: str
    raw_value: Any
    collected_at: str
    status: str = "COLLECTED"  # COLLECTED, ERROR, NOT_APPLICABLE
    error_message: Optional[str] = None


@dataclass
class AuditReportPayload:
    """Główna struktura raportu JSON przesyłanego do serwera centralnego."""
    schema_version: str
    report_id: str
    agent_id: str
    hostname: str
    os_family: str
    os_release: str
    architecture: str
    is_elevated: bool
    timestamp_utc: str
    policy_version: str
    boot_id: str
    measurements: List[Dict[str, Any]]


# =====================================================================
# KOLEKTORY SYSTEMOWE (HARDCODED / ALLOWLISTED - BRAK RCE)
# =====================================================================

class OSParameterCollector:
    """
    Klasa odpowiedzialna za bezpieczne pobieranie parametrów bezpieczeństwa
    bezpośrednio z natywnych mechanizmów systemu operacyjnego (WinReg, Win32 NetAPI, /proc, /etc).
    """

    def __init__(self) -> None:
        self.os_family = platform.system().lower()

    @staticmethod
    def check_elevated_privileges() -> bool:
        """Weryfikuje, czy proces działa z uprawnieniami Administratora / root."""
        try:
            if platform.system().lower() == "windows":
                return bool(ctypes.windll.shell32.IsUserAnAdmin())
            else:
                return os.geteuid() == 0  # type: ignore[attr-defined]
        except Exception as exc:
            logger.warning("Nie udało się zweryfikować uprawnień procesu: %s", exc)
            return False

    @staticmethod
    def get_system_boot_id() -> str:
        """Pobiera unikalny identyfikator bieżącego uruchomienia systemu (do detekcji All-Green Lie)."""
        try:
            if platform.system().lower() == "windows":
                kernel32 = ctypes.windll.kernel32
                uptime_ms = kernel32.GetTickCount64()
                boot_epoch = int(datetime.datetime.now(datetime.timezone.utc).timestamp() - (uptime_ms / 1000.0))
                # Zaokrąglenie do 10 sekund, aby uniknąć dryftu zegara
                return f"win-boot-{boot_epoch // 10}"
            else:
                boot_id_path = Path("/proc/sys/kernel/random/boot_id")
                if boot_id_path.exists():
                    return boot_id_path.read_text(encoding="ascii").strip()
        except Exception:
            pass
        return "boot-session-default"

    def collect_security_parameters(self, full_suite: bool = True) -> List[AuditMeasurement]:
        """Pobiera zestaw parametrów bezpieczeństwa CIS dla wykrytego systemu OS (22 reguły Windows / 20 reguł Linux)."""
        if self.os_family == "windows":
            core = [
                self._collect_windows_smbv1_status(),
                self._collect_windows_uac_lua_status(),
            ]
            if not full_suite:
                return core
            return core + [
                self._collect_windows_min_password_length(),
                self._collect_windows_firewall_status(),
                self._collect_windows_wdigest_status(),
                self._collect_windows_ntlmv2_level(),
                self._collect_windows_lsass_ppl(),
                self._collect_windows_ps_scriptblock_logging(),
                self._collect_windows_guest_account_status(),
                self._collect_windows_rdp_nla_status(),
                self._collect_windows_uefi_secureboot(),
                self._collect_windows_risky_listening_ports(),
                # Nowe reguły natywne CIS Windows Enterprise (Rozszerzenie do 22 reguł)
                self._collect_windows_llmnr_status(),
                self._collect_windows_smb_client_signing(),
                self._collect_windows_defender_realtime(),
                self._collect_windows_rdp_saved_passwords(),
                self._collect_windows_autorun_disabled(),
                self._collect_windows_bitlocker_c_status(),
                self._collect_windows_admin_account_status(),
                self._collect_windows_winrm_basic_auth(),
                self._collect_windows_inactivity_timeout(),
                self._collect_windows_cert_force_key_protection(),
            ]
        elif self.os_family == "linux":
            core = [
                self._collect_linux_sshd_permit_root_login(),
                self._collect_linux_ipv4_ip_forward(),
            ]
            if not full_suite:
                return core
            return core + [
                self._collect_linux_icmp_redirects(),
                self._collect_linux_shadow_permissions(),
                self._collect_linux_kernel_aslr(),
                self._collect_linux_auditd_service(),
                self._collect_linux_uid0_accounts(),
                self._collect_linux_sudoers_nopasswd(),
                self._collect_linux_grub_permissions(),
                self._collect_linux_risky_listening_ports(),
                # Nowe reguły natywne CIS Linux Enterprise (Rozszerzenie do 20 reguł)
                self._collect_linux_mac_status(),
                self._collect_linux_ip_source_route(),
                self._collect_linux_tcp_syncookies(),
                self._collect_linux_login_defs_encrypt_method(),
                self._collect_linux_sshd_password_auth(),
                self._collect_linux_suid_dumpable(),
                self._collect_linux_crontab_permissions(),
                self._collect_linux_icmp_echo_ignore_broadcasts(),
                self._collect_linux_log_martians(),
                self._collect_linux_login_defs_umask(),
            ]
        else:
            raise NotImplementedError(f"Nieobsługiwany system operacyjny: {self.os_family}")

    # -----------------------------------------------------------------
    # POMOCNICZY CZYTNIK REJESTRU WINDOWS (Natywny moduł winreg)
    # -----------------------------------------------------------------

    def _read_hklm_dword(
        self,
        check_id: str,
        category: str,
        title: str,
        reg_path: str,
        value_name: str,
    ) -> AuditMeasurement:
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        target_str = f"HKLM\\{reg_path}\\{value_name}"
        try:
            import winreg

            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                reg_path,
                0,
                winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
            ) as key:
                val, reg_type = winreg.QueryValueEx(key, value_name)
                return AuditMeasurement(
                    check_id=check_id,
                    category=category,
                    title=title,
                    collector_type="windows_registry",
                    target=target_str,
                    raw_value={"value": int(val), "reg_type": int(reg_type)},
                    collected_at=now,
                    status="COLLECTED",
                )
        except FileNotFoundError:
            return AuditMeasurement(
                check_id=check_id,
                category=category,
                title=title,
                collector_type="windows_registry",
                target=target_str,
                raw_value={"value": None, "key_exists": False},
                collected_at=now,
                status="COLLECTED",
            )
        except Exception as exc:
            return AuditMeasurement(
                check_id=check_id,
                category=category,
                title=title,
                collector_type="windows_registry",
                target=target_str,
                raw_value=None,
                collected_at=now,
                status="ERROR",
                error_message=str(exc),
            )

    # -----------------------------------------------------------------
    # KOLEKTORY WINDOWS (8 Reguł CIS)
    # -----------------------------------------------------------------

    def _collect_windows_smbv1_status(self) -> AuditMeasurement:
        """WIN-CIS-18.3.1: Weryfikacja wyłączenia protokołu SMBv1."""
        return self._read_hklm_dword(
            check_id="WIN-CIS-18.3.1",
            category="Network Security",
            title="Ensure SMBv1 Server protocol is disabled",
            reg_path=r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            value_name="SMB1",
        )

    def _collect_windows_uac_lua_status(self) -> AuditMeasurement:
        """WIN-CIS-2.3.17.1: Weryfikacja User Account Control (EnableLUA)."""
        return self._read_hklm_dword(
            check_id="WIN-CIS-2.3.17.1",
            category="Privilege Escalation",
            title="Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is Enabled",
            reg_path=r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            value_name="EnableLUA",
        )

    def _collect_windows_min_password_length(self) -> AuditMeasurement:
        """
        WIN-CIS-1.1.1: Weryfikacja minimalnej długości hasła poprzez bezpośrednie
        wywołanie natywnej funkcji Win32 API `NetUserModalsGet` (netapi32.dll) przez ctypes.
        """
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        target_str = "Win32API::NetUserModalsGet(level=0)->usrmod0_min_passwd_len"

        class USER_MODALS_INFO_0(ctypes.Structure):
            _fields_ = [
                ("usrmod0_min_passwd_len", ctypes.c_uint32),
                ("usrmod0_max_passwd_age", ctypes.c_uint32),
                ("usrmod0_min_passwd_age", ctypes.c_uint32),
                ("usrmod0_force_logoff", ctypes.c_uint32),
                ("usrmod0_password_hist_len", ctypes.c_uint32),
            ]

        try:
            netapi32 = ctypes.windll.netapi32
            buf_ptr = ctypes.POINTER(USER_MODALS_INFO_0)()
            status = netapi32.NetUserModalsGet(None, 0, ctypes.byref(buf_ptr))
            if status == 0 and buf_ptr:
                min_len = int(buf_ptr.contents.usrmod0_min_passwd_len)
                max_age_days = int(buf_ptr.contents.usrmod0_max_passwd_age) // 86400
                hist_len = int(buf_ptr.contents.usrmod0_password_hist_len)
                netapi32.NetApiBufferFree(buf_ptr)
                return AuditMeasurement(
                    check_id="WIN-CIS-1.1.1",
                    category="Password & Account Policies",
                    title="Ensure 'Minimum password length' is set to 14 or more characters",
                    collector_type="windows_security_policy",
                    target=target_str,
                    raw_value={
                        "value": min_len,
                        "password_history_len": hist_len,
                        "max_password_age_days": max_age_days,
                    },
                    collected_at=now,
                    status="COLLECTED",
                )
            return AuditMeasurement(
                check_id="WIN-CIS-1.1.1",
                category="Password & Account Policies",
                title="Ensure 'Minimum password length' is set to 14 or more characters",
                collector_type="windows_security_policy",
                target=target_str,
                raw_value=None,
                collected_at=now,
                status="ERROR",
                error_message=f"NetUserModalsGet returned code {status}",
            )
        except Exception as exc:
            return AuditMeasurement(
                check_id="WIN-CIS-1.1.1",
                category="Password & Account Policies",
                title="Ensure 'Minimum password length' is set to 14 or more characters",
                collector_type="windows_security_policy",
                target=target_str,
                raw_value=None,
                collected_at=now,
                status="ERROR",
                error_message=str(exc),
            )

    def _collect_windows_firewall_status(self) -> AuditMeasurement:
        """WIN-CIS-9.1.1: Weryfikacja stanu zapory Windows Defender Firewall."""
        return self._read_hklm_dword(
            check_id="WIN-CIS-9.1.1",
            category="Host Firewall & Endpoint Protection",
            title="Ensure 'Windows Defender Firewall: Standard/Domain Profile: Firewall state' is set to 'On'",
            reg_path=r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
            value_name="EnableFirewall",
        )

    def _collect_windows_wdigest_status(self) -> AuditMeasurement:
        """WIN-CIS-18.4.2: Weryfikacja blokady przechowywania haseł jawnych WDigest w LSASS."""
        return self._read_hklm_dword(
            check_id="WIN-CIS-18.4.2",
            category="Credential Protection",
            title="Ensure 'WDigest Authentication' is disabled (UseLogonCredential = 0)",
            reg_path=r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
            value_name="UseLogonCredential",
        )

    def _collect_windows_ntlmv2_level(self) -> AuditMeasurement:
        """WIN-CIS-2.3.11.7: Weryfikacja poziomu uwierzytelniania LAN Manager (LmCompatibilityLevel)."""
        return self._read_hklm_dword(
            check_id="WIN-CIS-2.3.11.7",
            category="Credential Protection",
            title="Ensure 'Network security: LAN Manager authentication level' is set to NTLMv2 only",
            reg_path=r"SYSTEM\CurrentControlSet\Control\Lsa",
            value_name="LmCompatibilityLevel",
        )

    def _collect_windows_lsass_ppl(self) -> AuditMeasurement:
        """WIN-CIS-18.9.47.1: Weryfikacja ochrony procesu LSASS jako Protected Process Light (RunAsPPL)."""
        return self._read_hklm_dword(
            check_id="WIN-CIS-18.9.47.1",
            category="Credential Protection",
            title="Ensure LSASS runs as a Protected Process Light (RunAsPPL = 1 or 2)",
            reg_path=r"SYSTEM\CurrentControlSet\Control\Lsa",
            value_name="RunAsPPL",
        )

    def _collect_windows_ps_scriptblock_logging(self) -> AuditMeasurement:
        """WIN-CIS-18.10.57.1: Weryfikacja włączenia logowania bloków skryptów PowerShell."""
        return self._read_hklm_dword(
            check_id="WIN-CIS-18.10.57.1",
            category="Audit & Logging",
            title="Ensure 'Turn on PowerShell Script Block Logging' is set to 'Enabled'",
            reg_path=r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
            value_name="EnableScriptBlockLogging",
        )

    def _collect_windows_guest_account_status(self) -> AuditMeasurement:
        """WIN-CIS-2.3.1.2: Weryfikacja blokady wbudowanego konta Gościa (Guest / Gość) przez Win32 NetUserGetInfo."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        target_str = "Win32API::NetUserGetInfo(Guest/Gość, level=1)->usri1_flags(UF_ACCOUNTDISABLE)"

        class USER_INFO_1(ctypes.Structure):
            _fields_ = [
                ("usri1_name", ctypes.c_wchar_p),
                ("usri1_password", ctypes.c_wchar_p),
                ("usri1_password_age", ctypes.c_uint32),
                ("usri1_priv", ctypes.c_uint32),
                ("usri1_home_dir", ctypes.c_wchar_p),
                ("usri1_comment", ctypes.c_wchar_p),
                ("usri1_flags", ctypes.c_uint32),
                ("usri1_script_path", ctypes.c_wchar_p),
            ]

        UF_ACCOUNTDISABLE = 0x0002
        try:
            netapi32 = ctypes.windll.netapi32
            for candidate_name in ("Guest", "Gość"):
                buf_ptr = ctypes.POINTER(USER_INFO_1)()
                status = netapi32.NetUserGetInfo(None, candidate_name, 1, ctypes.byref(buf_ptr))
                if status == 0 and buf_ptr:
                    flags = int(buf_ptr.contents.usri1_flags)
                    netapi32.NetApiBufferFree(buf_ptr)
                    is_disabled = bool(flags & UF_ACCOUNTDISABLE)
                    # value=0 oznacza konto wyłączone (zgodne z CIS), value=1 oznacza aktywne!
                    return AuditMeasurement(
                        check_id="WIN-CIS-2.3.1.2",
                        category="Password & Account Policies",
                        title="Ensure 'Accounts: Guest account status' is set to 'Disabled'",
                        collector_type="windows_sam_account",
                        target=target_str,
                        raw_value={
                            "value": 0 if is_disabled else 1,
                            "account_name": candidate_name,
                            "is_disabled": is_disabled,
                            "usri1_flags_hex": hex(flags),
                        },
                        collected_at=now,
                        status="COLLECTED",
                    )
            return AuditMeasurement(
                check_id="WIN-CIS-2.3.1.2",
                category="Password & Account Policies",
                title="Ensure 'Accounts: Guest account status' is set to 'Disabled'",
                collector_type="windows_sam_account",
                target=target_str,
                raw_value={"value": 0, "account_exists": False, "is_disabled": True},
                collected_at=now,
                status="COLLECTED",
            )
        except Exception as exc:
            return AuditMeasurement(
                check_id="WIN-CIS-2.3.1.2",
                category="Password & Account Policies",
                title="Ensure 'Accounts: Guest account status' is set to 'Disabled'",
                collector_type="windows_sam_account",
                target=target_str,
                raw_value=None,
                collected_at=now,
                status="ERROR",
                error_message=str(exc),
            )

    def _collect_windows_rdp_nla_status(self) -> AuditMeasurement:
        """WIN-CIS-18.9.102.2: Weryfikacja wymuszenia Network Level Authentication (NLA) dla sesji RDP."""
        return self._read_hklm_dword(
            check_id="WIN-CIS-18.9.102.2",
            category="Remote Access & RDP Hardening",
            title="Ensure 'Require user authentication for remote connections by using Network Level Authentication (RDP NLA)' is Enabled",
            reg_path=r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
            value_name="UserAuthentication",
        )

    def _collect_windows_uefi_secureboot(self) -> AuditMeasurement:
        """WIN-CIS-18.9.10.1: Weryfikacja aktywności UEFI Secure Boot."""
        return self._read_hklm_dword(
            check_id="WIN-CIS-18.9.10.1",
            category="Hardware & Boot Integrity",
            title="Ensure UEFI Secure Boot is enabled to prevent bootkit/rootkit execution",
            reg_path=r"SYSTEM\CurrentControlSet\Control\SecureBoot\State",
            value_name="UEFISecureBootEnabled",
        )

    def _collect_windows_risky_listening_ports(self) -> AuditMeasurement:
        """WIN-NET-SURFACE-01: Weryfikacja braku nasłuchu na niebezpiecznych portach TCP (21, 23, 69, 513, 514)."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        forbidden_ports = [21, 23, 69, 513, 514]
        exposed: List[int] = []
        try:
            for port in forbidden_ports:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.08)
                    if s.connect_ex(("127.0.0.1", port)) == 0:
                        exposed.append(port)
            return AuditMeasurement(
                check_id="WIN-NET-SURFACE-01",
                category="Network Attack Surface",
                title="Ensure no high-risk cleartext or legacy TCP ports are listening (Telnet/23, FTP/21, RSH/514, TFTP/69)",
                collector_type="network_listening_ports",
                target="TCP::127.0.0.1:[21,23,69,513,514]",
                raw_value={"value": len(exposed), "exposed_ports": exposed, "checked_ports": forbidden_ports},
                collected_at=now,
                status="COLLECTED",
            )
        except Exception as exc:
            return AuditMeasurement(
                check_id="WIN-NET-SURFACE-01",
                category="Network Attack Surface",
                title="Ensure no high-risk cleartext or legacy TCP ports are listening (Telnet/23, FTP/21, RSH/514, TFTP/69)",
                collector_type="network_listening_ports",
                target="TCP::127.0.0.1:[21,23,69,513,514]",
                raw_value=None,
                collected_at=now,
                status="ERROR",
                error_message=str(exc),
            )

    def _collect_windows_llmnr_status(self) -> AuditMeasurement:
        """WIN-CIS-18.9.30.2: Weryfikacja wyłączenia multicastu LLMNR."""
        return self._read_hklm_dword(
            check_id="WIN-CIS-18.9.30.2",
            category="Network Protocol Hardening",
            title="Ensure 'Turn off multicast name resolution' (LLMNR) is set to 'Enabled'",
            reg_path=r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
            value_name="EnableMulticast",
        )

    def _collect_windows_smb_client_signing(self) -> AuditMeasurement:
        """WIN-CIS-2.3.7.4: Wymuszenie podpisywania cyfrowego SMB przez klienta."""
        return self._read_hklm_dword(
            check_id="WIN-CIS-2.3.7.4",
            category="Network Security",
            title="Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'",
            reg_path=r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
            value_name="RequireSecuritySignature",
        )

    def _collect_windows_defender_realtime(self) -> AuditMeasurement:
        """WIN-CIS-18.9.5.1: Weryfikacja ochrony w czasie rzeczywistym Windows Defender."""
        return self._read_hklm_dword(
            check_id="WIN-CIS-18.9.5.1",
            category="Endpoint Protection & Antivirus",
            title="Ensure 'Windows Defender Antivirus: Real-time Protection' is Enabled",
            reg_path=r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
            value_name="DisableRealtimeMonitoring",
        )

    def _collect_windows_rdp_saved_passwords(self) -> AuditMeasurement:
        """WIN-CIS-18.8.19.2: Blokada zapisywania haseł RDP w kliencie."""
        return self._read_hklm_dword(
            check_id="WIN-CIS-18.8.19.2",
            category="Credential Protection",
            title="Ensure 'Do not allow passwords to be saved' in Remote Desktop Connection is Enabled",
            reg_path=r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
            value_name="DisablePasswordSaving",
        )

    def _collect_windows_autorun_disabled(self) -> AuditMeasurement:
        """WIN-CIS-18.5.11.2: Wyłączenie autoodtwarzania dysków wymiennych."""
        return self._read_hklm_dword(
            check_id="WIN-CIS-18.5.11.2",
            category="Removable Media & Peripherals",
            title="Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'",
            reg_path=r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            value_name="NoDriveTypeAutoRun",
        )

    def _collect_windows_bitlocker_c_status(self) -> AuditMeasurement:
        """WIN-CIS-18.9.15.1: Weryfikacja szyfrowania BitLocker na woluminie systemowym C:"""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        try:
            proc = subprocess.run(
                ["manage-bde.exe", "-status", "C:"],
                shell=False,
                capture_output=True,
                text=True,
                timeout=6,
                check=False,
            )
            out = (proc.stdout or "").lower()
            is_on = "protection on" in out or "ochrona włączona" in out or "ochrona wlaczona" in out
            return AuditMeasurement(
                check_id="WIN-CIS-18.9.15.1",
                category="Data-at-Rest & Encryption",
                title="Ensure BitLocker Drive Encryption protection is active on System Volume (C:)",
                collector_type="windows_bitlocker_status",
                target="Volume::C:\\manage-bde",
                raw_value={"value": 1 if is_on else 0, "protection_active": is_on, "details": (proc.stdout or "").strip()[:160]},
                collected_at=now,
                status="COLLECTED",
            )
        except Exception as exc:
            return AuditMeasurement(
                check_id="WIN-CIS-18.9.15.1",
                category="Data-at-Rest & Encryption",
                title="Ensure BitLocker Drive Encryption protection is active on System Volume (C:)",
                collector_type="windows_bitlocker_status",
                target="Volume::C:\\manage-bde",
                raw_value={"value": 0, "error": str(exc)},
                collected_at=now,
                status="COLLECTED",
            )

    def _collect_windows_admin_account_status(self) -> AuditMeasurement:
        """WIN-CIS-2.3.1.5: Weryfikacja blokady wbudowanego konta Administrator (NetUserGetInfo)."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        target_str = "Win32API::NetUserGetInfo(Administrator, level=1)->usri1_flags"

        class USER_INFO_1(ctypes.Structure):
            _fields_ = [
                ("usri1_name", ctypes.c_wchar_p),
                ("usri1_password", ctypes.c_wchar_p),
                ("usri1_password_age", ctypes.c_uint32),
                ("usri1_priv", ctypes.c_uint32),
                ("usri1_home_dir", ctypes.c_wchar_p),
                ("usri1_comment", ctypes.c_wchar_p),
                ("usri1_flags", ctypes.c_uint32),
                ("usri1_script_path", ctypes.c_wchar_p),
            ]

        UF_ACCOUNTDISABLE = 0x0002
        try:
            netapi32 = ctypes.windll.netapi32
            for candidate_name in ("Administrator", "administrator"):
                buf_ptr = ctypes.POINTER(USER_INFO_1)()
                status = netapi32.NetUserGetInfo(None, candidate_name, 1, ctypes.byref(buf_ptr))
                if status == 0 and buf_ptr:
                    flags = int(buf_ptr.contents.usri1_flags)
                    netapi32.NetApiBufferFree(buf_ptr)
                    is_disabled = bool(flags & UF_ACCOUNTDISABLE)
                    return AuditMeasurement(
                        check_id="WIN-CIS-2.3.1.5",
                        category="Password & Account Policies",
                        title="Ensure 'Accounts: Administrator account status' is set to 'Disabled' or renamed",
                        collector_type="windows_sam_admin_status",
                        target=target_str,
                        raw_value={"value": 0 if is_disabled else 1, "is_disabled": is_disabled, "account_name": candidate_name},
                        collected_at=now,
                        status="COLLECTED",
                    )
            return AuditMeasurement(
                check_id="WIN-CIS-2.3.1.5",
                category="Password & Account Policies",
                title="Ensure 'Accounts: Administrator account status' is set to 'Disabled' or renamed",
                collector_type="windows_sam_admin_status",
                target=target_str,
                raw_value={"value": 0, "is_renamed_or_missing": True},
                collected_at=now,
                status="COLLECTED",
            )
        except Exception as exc:
            return AuditMeasurement(
                check_id="WIN-CIS-2.3.1.5",
                category="Password & Account Policies",
                title="Ensure 'Accounts: Administrator account status' is set to 'Disabled' or renamed",
                collector_type="windows_sam_admin_status",
                target=target_str,
                raw_value=None,
                collected_at=now,
                status="ERROR",
                error_message=str(exc),
            )

    def _collect_windows_winrm_basic_auth(self) -> AuditMeasurement:
        """WIN-CIS-18.9.84.1: Blokada uwierzytelniania podstawowego w WinRM."""
        return self._read_hklm_dword(
            check_id="WIN-CIS-18.9.84.1",
            category="Remote Management & WinRM",
            title="Ensure Windows Remote Management (WinRM) Basic Authentication is disabled",
            reg_path=r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Client",
            value_name="AllowBasic",
        )

    def _collect_windows_inactivity_timeout(self) -> AuditMeasurement:
        """WIN-CIS-18.9.102.3: Limit braku aktywności stacji (blokada ekranu)."""
        return self._read_hklm_dword(
            check_id="WIN-CIS-18.9.102.3",
            category="Session Management & Screen Lock",
            title="Ensure 'Machine inactivity limit' is set to 900 or fewer seconds (Screen Saver Lockout)",
            reg_path=r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            value_name="InactivityTimeoutSecs",
        )

    def _collect_windows_cert_force_key_protection(self) -> AuditMeasurement:
        """WIN-CIS-18.4.1: Wymuszenie silnej ochrony klucza prywatnego certyfikatów."""
        return self._read_hklm_dword(
            check_id="WIN-CIS-18.4.1",
            category="Cryptography & PKI",
            title="Ensure 'Strong private key protection for stored certificates' is enforced",
            reg_path=r"SOFTWARE\Policies\Microsoft\Cryptography",
            value_name="ForceKeyProtection",
        )

    # -----------------------------------------------------------------
    # KOLEKTORY LINUX (10 Reguł CIS)
    # -----------------------------------------------------------------

    def _collect_linux_sshd_permit_root_login(self) -> AuditMeasurement:
        """LNX-CIS-5.2.8: Weryfikacja blokady logowania root przez SSH."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        target_path = Path("/etc/ssh/sshd_config")
        try:
            if not target_path.exists():
                return AuditMeasurement(
                    check_id="LNX-CIS-5.2.8",
                    category="SSH Hardening",
                    title="Ensure SSH root login is disabled",
                    collector_type="linux_sshd_effective_config",
                    target=str(target_path),
                    raw_value={"directive": "PermitRootLogin", "value": None, "file_exists": False},
                    collected_at=now,
                    status="NOT_APPLICABLE",
                )

            directive_value = "default_unset"
            content = target_path.read_text(encoding="utf-8", errors="replace")
            for raw_line in content.splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                match = re.match(r"^PermitRootLogin\s+(\S+)", line, re.IGNORECASE)
                if match:
                    directive_value = match.group(1).lower()
                    break

            return AuditMeasurement(
                check_id="LNX-CIS-5.2.8",
                category="SSH Hardening",
                title="Ensure SSH root login is disabled",
                collector_type="linux_sshd_effective_config",
                target=str(target_path),
                raw_value={"directive": "PermitRootLogin", "value": directive_value},
                collected_at=now,
                status="COLLECTED",
            )
        except Exception as exc:
            return AuditMeasurement(
                check_id="LNX-CIS-5.2.8",
                category="SSH Hardening",
                title="Ensure SSH root login is disabled",
                collector_type="linux_sshd_effective_config",
                target=str(target_path),
                raw_value=None,
                collected_at=now,
                status="ERROR",
                error_message=str(exc),
            )

    def _collect_linux_ipv4_ip_forward(self) -> AuditMeasurement:
        """LNX-CIS-3.1.1: Weryfikacja wyłączenia przekazywania pakietów IPv4."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        proc_path = Path("/proc/sys/net/ipv4/ip_forward")
        try:
            raw_text = proc_path.read_text(encoding="ascii").strip()
            return AuditMeasurement(
                check_id="LNX-CIS-3.1.1",
                category="Kernel Network Hardening",
                title="Ensure IPv4 packet forwarding is disabled",
                collector_type="linux_proc_sysctl",
                target="net.ipv4.ip_forward",
                raw_value={"value": int(raw_text)},
                collected_at=now,
                status="COLLECTED",
            )
        except Exception as exc:
            return AuditMeasurement(
                check_id="LNX-CIS-3.1.1",
                category="Kernel Network Hardening",
                title="Ensure IPv4 packet forwarding is disabled",
                collector_type="linux_proc_sysctl",
                target="net.ipv4.ip_forward",
                raw_value=None,
                collected_at=now,
                status="ERROR",
                error_message=str(exc),
            )

    def _collect_linux_icmp_redirects(self) -> AuditMeasurement:
        """LNX-CIS-3.3.5: Weryfikacja odrzucania pakietów ICMP Redirect."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        keys = {
            "net.ipv4.conf.all.accept_redirects": Path("/proc/sys/net/ipv4/conf/all/accept_redirects"),
            "net.ipv4.conf.default.accept_redirects": Path("/proc/sys/net/ipv4/conf/default/accept_redirects"),
        }
        try:
            values = {k: int(p.read_text(encoding="ascii").strip()) for k, p in keys.items()}
            return AuditMeasurement(
                check_id="LNX-CIS-3.3.5",
                category="Kernel Network Hardening",
                title="Ensure ICMP redirects are not accepted",
                collector_type="linux_proc_sysctl",
                target="net.ipv4.conf.*.accept_redirects",
                raw_value={"values": values},
                collected_at=now,
                status="COLLECTED",
            )
        except Exception as exc:
            return AuditMeasurement(
                check_id="LNX-CIS-3.3.5",
                category="Kernel Network Hardening",
                title="Ensure ICMP redirects are not accepted",
                collector_type="linux_proc_sysctl",
                target="net.ipv4.conf.*.accept_redirects",
                raw_value=None,
                collected_at=now,
                status="ERROR",
                error_message=str(exc),
            )

    def _collect_linux_shadow_permissions(self) -> AuditMeasurement:
        """LNX-CIS-6.1.10: Weryfikacja uprawnień i właściciela pliku /etc/shadow."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        shadow_path = Path("/etc/shadow")
        try:
            import grp
            import pwd

            st = shadow_path.stat()
            mode_octal = oct(st.st_mode & 0o777)[2:].zfill(4)
            owner_name = pwd.getpwuid(st.st_uid).pw_name
            group_name = grp.getgrgid(st.st_gid).gr_name
            return AuditMeasurement(
                check_id="LNX-CIS-6.1.10",
                category="Filesystem Integrity & Permissions",
                title="Ensure permissions on /etc/shadow are configured (0640 or more restrictive)",
                collector_type="linux_file_stat",
                target="/etc/shadow",
                raw_value={
                    "uid": st.st_uid,
                    "gid": st.st_gid,
                    "owner": owner_name,
                    "group": group_name,
                    "mode_octal": mode_octal,
                },
                collected_at=now,
                status="COLLECTED",
            )
        except Exception as exc:
            return AuditMeasurement(
                check_id="LNX-CIS-6.1.10",
                category="Filesystem Integrity & Permissions",
                title="Ensure permissions on /etc/shadow are configured (0640 or more restrictive)",
                collector_type="linux_file_stat",
                target="/etc/shadow",
                raw_value=None,
                collected_at=now,
                status="ERROR",
                error_message=str(exc),
            )

    def _collect_linux_kernel_aslr(self) -> AuditMeasurement:
        """LNX-CIS-1.5.1: Weryfikacja aktywności ASLR w jądrze (kernel.randomize_va_space = 2)."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        proc_path = Path("/proc/sys/kernel/randomize_va_space")
        try:
            val = int(proc_path.read_text(encoding="ascii").strip())
            return AuditMeasurement(
                check_id="LNX-CIS-1.5.1",
                category="Kernel Memory Protection",
                title="Ensure Address Space Layout Randomization (ASLR) is fully enabled",
                collector_type="linux_proc_sysctl",
                target="kernel.randomize_va_space",
                raw_value={"value": val},
                collected_at=now,
                status="COLLECTED",
            )
        except Exception as exc:
            return AuditMeasurement(
                check_id="LNX-CIS-1.5.1",
                category="Kernel Memory Protection",
                title="Ensure Address Space Layout Randomization (ASLR) is fully enabled",
                collector_type="linux_proc_sysctl",
                target="kernel.randomize_va_space",
                raw_value=None,
                collected_at=now,
                status="ERROR",
                error_message=str(exc),
            )

    def _collect_linux_auditd_service(self) -> AuditMeasurement:
        """LNX-CIS-4.1.1.1: Weryfikacja stanu usługi auditd (bez wywoływania powłoki shell=False)."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        try:
            proc = subprocess.run(
                ["/bin/systemctl", "is-active", "auditd.service"],
                shell=False,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            state = proc.stdout.strip() or "inactive"
            return AuditMeasurement(
                check_id="LNX-CIS-4.1.1.1",
                category="Audit & Logging",
                title="Ensure auditd service is enabled and active",
                collector_type="linux_systemd_service",
                target="auditd.service",
                raw_value={"value": state},
                collected_at=now,
                status="COLLECTED",
            )
        except Exception as exc:
            return AuditMeasurement(
                check_id="LNX-CIS-4.1.1.1",
                category="Audit & Logging",
                title="Ensure auditd service is enabled and active",
                collector_type="linux_systemd_service",
                target="auditd.service",
                raw_value=None,
                collected_at=now,
                status="ERROR",
                error_message=str(exc),
            )

    def _collect_linux_uid0_accounts(self) -> AuditMeasurement:
        """LNX-CIS-6.2.5: Weryfikacja, czy root jest jedynym kontem z UID=0 w /etc/passwd."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        passwd_path = Path("/etc/passwd")
        try:
            non_root_uid0: List[str] = []
            for raw_line in passwd_path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(":")
                if len(parts) >= 3:
                    username, uid_str = parts[0], parts[2]
                    if uid_str == "0" and username != "root":
                        non_root_uid0.append(username)
            return AuditMeasurement(
                check_id="LNX-CIS-6.2.5",
                category="Privilege Escalation",
                title="Ensure root is the only UID 0 account in /etc/passwd",
                collector_type="linux_passwd_uid0",
                target="/etc/passwd",
                raw_value={"value": len(non_root_uid0), "non_root_uid0_accounts": non_root_uid0},
                collected_at=now,
                status="COLLECTED",
            )
        except Exception as exc:
            return AuditMeasurement(
                check_id="LNX-CIS-6.2.5",
                category="Privilege Escalation",
                title="Ensure root is the only UID 0 account in /etc/passwd",
                collector_type="linux_passwd_uid0",
                target="/etc/passwd",
                raw_value=None,
                collected_at=now,
                status="ERROR",
                error_message=str(exc),
            )

    def _collect_linux_sudoers_nopasswd(self) -> AuditMeasurement:
        """LNX-CIS-5.3.3: Weryfikacja braku dyrektyw NOPASSWD w /etc/sudoers i /etc/sudoers.d/*."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        try:
            nopasswd_lines: List[str] = []
            candidate_files = [Path("/etc/sudoers")]
            sudoers_d = Path("/etc/sudoers.d")
            if sudoers_d.exists() and sudoers_d.is_dir():
                candidate_files.extend(sorted(sudoers_d.iterdir()))

            for fpath in candidate_files:
                if not fpath.is_file():
                    continue
                for raw_line in fpath.read_text(encoding="utf-8", errors="replace").splitlines():
                    line = raw_line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "NOPASSWD" in line:
                        nopasswd_lines.append(f"{fpath.name}: {line}")

            return AuditMeasurement(
                check_id="LNX-CIS-5.3.3",
                category="Privilege Escalation",
                title="Ensure sudoers configuration does not allow passwordless privilege escalation (NOPASSWD)",
                collector_type="linux_sudoers_nopasswd",
                target="/etc/sudoers",
                raw_value={"value": len(nopasswd_lines), "matches": nopasswd_lines[:5]},
                collected_at=now,
                status="COLLECTED",
            )
        except Exception as exc:
            return AuditMeasurement(
                check_id="LNX-CIS-5.3.3",
                category="Privilege Escalation",
                title="Ensure sudoers configuration does not allow passwordless privilege escalation (NOPASSWD)",
                collector_type="linux_sudoers_nopasswd",
                target="/etc/sudoers",
                raw_value=None,
                collected_at=now,
                status="ERROR",
                error_message=str(exc),
            )

    def _collect_linux_grub_permissions(self) -> AuditMeasurement:
        """LNX-CIS-1.4.1: Weryfikacja uprawnień pliku konfiguracyjnego bootloadera /boot/grub/grub.cfg."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        grub_path = Path("/boot/grub/grub.cfg")
        if not grub_path.exists():
            alt_path = Path("/boot/grub2/grub.cfg")
            if alt_path.exists():
                grub_path = alt_path
        try:
            if not grub_path.exists():
                return AuditMeasurement(
                    check_id="LNX-CIS-1.4.1",
                    category="Hardware & Boot Integrity",
                    title="Ensure bootloader configuration (/boot/grub/grub.cfg) permissions are 0400/0600 root:root",
                    collector_type="linux_file_stat",
                    target="/boot/grub/grub.cfg",
                    raw_value={"file_exists": False},
                    collected_at=now,
                    status="NOT_APPLICABLE",
                )
            import grp
            import pwd

            st = grub_path.stat()
            mode_octal = oct(st.st_mode & 0o777)[2:].zfill(4)
            owner_name = pwd.getpwuid(st.st_uid).pw_name
            group_name = grp.getgrgid(st.st_gid).gr_name
            return AuditMeasurement(
                check_id="LNX-CIS-1.4.1",
                category="Hardware & Boot Integrity",
                title="Ensure bootloader configuration (/boot/grub/grub.cfg) permissions are 0400/0600 root:root",
                collector_type="linux_file_stat",
                target=str(grub_path),
                raw_value={
                    "uid": st.st_uid,
                    "gid": st.st_gid,
                    "owner": owner_name,
                    "group": group_name,
                    "mode_octal": mode_octal,
                },
                collected_at=now,
                status="COLLECTED",
            )
        except Exception as exc:
            return AuditMeasurement(
                check_id="LNX-CIS-1.4.1",
                category="Hardware & Boot Integrity",
                title="Ensure bootloader configuration (/boot/grub/grub.cfg) permissions are 0400/0600 root:root",
                collector_type="linux_file_stat",
                target="/boot/grub/grub.cfg",
                raw_value=None,
                collected_at=now,
                status="ERROR",
                error_message=str(exc),
            )

    def _collect_linux_risky_listening_ports(self) -> AuditMeasurement:
        """LNX-NET-SURFACE-01: Weryfikacja braku otwartych portów usług nieszyfrowanych w /proc/net/tcp."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        forbidden_ports = {21, 23, 69, 513, 514, 6000}
        exposed: List[int] = []
        try:
            for proc_net in (Path("/proc/net/tcp"), Path("/proc/net/tcp6")):
                if not proc_net.exists():
                    continue
                for line in proc_net.read_text(encoding="ascii", errors="replace").splitlines()[1:]:
                    cols = line.split()
                    if len(cols) >= 4 and cols[3] == "0A":  # 0A = TCP_LISTEN
                        local_addr = cols[1]
                        if ":" in local_addr:
                            port_hex = local_addr.split(":")[1]
                            port_num = int(port_hex, 16)
                            if port_num in forbidden_ports and port_num not in exposed:
                                exposed.append(port_num)
            return AuditMeasurement(
                check_id="LNX-NET-SURFACE-01",
                category="Network Attack Surface",
                title="Ensure no high-risk cleartext TCP ports are listening (Telnet/23, FTP/21, RSH/514, X11/6000)",
                collector_type="network_listening_ports",
                target="/proc/net/tcp",
                raw_value={"value": len(exposed), "exposed_ports": sorted(exposed)},
                collected_at=now,
                status="COLLECTED",
            )
        except Exception as exc:
            return AuditMeasurement(
                check_id="LNX-NET-SURFACE-01",
                category="Network Attack Surface",
                title="Ensure no high-risk cleartext TCP ports are listening (Telnet/23, FTP/21, RSH/514, X11/6000)",
                collector_type="network_listening_ports",
                target="/proc/net/tcp",
                raw_value=None,
                collected_at=now,
                status="ERROR",
                error_message=str(exc),
            )

    def _collect_linux_mac_status(self) -> AuditMeasurement:
        """LNX-CIS-1.6.1: Weryfikacja aktywności AppArmor lub SELinux."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        apparmor_path = Path("/sys/kernel/security/apparmor/profiles")
        selinux_path = Path("/sys/fs/selinux/enforce")
        status_val = "disabled"
        try:
            if apparmor_path.exists():
                text = apparmor_path.read_text(encoding="ascii", errors="replace").strip()
                if text:
                    status_val = "enforcing"
            elif selinux_path.exists():
                text = selinux_path.read_text(encoding="ascii", errors="replace").strip()
                if text == "1":
                    status_val = "enforcing"
            return AuditMeasurement(
                check_id="LNX-CIS-1.6.1",
                category="Mandatory Access Control",
                title="Ensure AppArmor or SELinux is installed, enabled, and in enforcing mode",
                collector_type="linux_mac_status",
                target="/sys/kernel/security/apparmor;/sys/fs/selinux",
                raw_value={"value": status_val},
                collected_at=now,
                status="COLLECTED",
            )
        except Exception as exc:
            return AuditMeasurement(
                check_id="LNX-CIS-1.6.1",
                category="Mandatory Access Control",
                title="Ensure AppArmor or SELinux is installed, enabled, and in enforcing mode",
                collector_type="linux_mac_status",
                target="/sys/kernel/security/apparmor;/sys/fs/selinux",
                raw_value=None,
                collected_at=now,
                status="ERROR",
                error_message=str(exc),
            )

    def _collect_linux_ip_source_route(self) -> AuditMeasurement:
        """LNX-CIS-3.3.1: Weryfikacja blokady pakietów IP Source Routed."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        keys = {
            "net.ipv4.conf.all.accept_source_route": Path("/proc/sys/net/ipv4/conf/all/accept_source_route"),
            "net.ipv4.conf.default.accept_source_route": Path("/proc/sys/net/ipv4/conf/default/accept_source_route"),
        }
        try:
            vals = {k: int(p.read_text(encoding="ascii").strip()) for k, p in keys.items()}
            return AuditMeasurement(
                check_id="LNX-CIS-3.3.1",
                category="Kernel Network Hardening",
                title="Ensure source routed packets are not accepted (accept_source_route = 0)",
                collector_type="linux_proc_sysctl",
                target="net.ipv4.conf.*.accept_source_route",
                raw_value={"values": vals},
                collected_at=now,
                status="COLLECTED",
            )
        except Exception as exc:
            return AuditMeasurement(
                check_id="LNX-CIS-3.3.1",
                category="Kernel Network Hardening",
                title="Ensure source routed packets are not accepted (accept_source_route = 0)",
                collector_type="linux_proc_sysctl",
                target="net.ipv4.conf.*.accept_source_route",
                raw_value=None,
                collected_at=now,
                status="ERROR",
                error_message=str(exc),
            )

    def _collect_linux_tcp_syncookies(self) -> AuditMeasurement:
        """LNX-CIS-3.3.2: Weryfikacja włączenia TCP SYN Cookies."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        p = Path("/proc/sys/net/ipv4/tcp_syncookies")
        try:
            val = int(p.read_text(encoding="ascii").strip())
            return AuditMeasurement(
                check_id="LNX-CIS-3.3.2",
                category="Kernel Network Hardening",
                title="Ensure TCP SYN Cookies are enabled (net.ipv4.tcp_syncookies = 1)",
                collector_type="linux_proc_sysctl",
                target="net.ipv4.tcp_syncookies",
                raw_value={"value": val},
                collected_at=now,
                status="COLLECTED",
            )
        except Exception as exc:
            return AuditMeasurement(
                check_id="LNX-CIS-3.3.2",
                category="Kernel Network Hardening",
                title="Ensure TCP SYN Cookies are enabled (net.ipv4.tcp_syncookies = 1)",
                collector_type="linux_proc_sysctl",
                target="net.ipv4.tcp_syncookies",
                raw_value=None,
                collected_at=now,
                status="ERROR",
                error_message=str(exc),
            )

    def _collect_linux_login_defs_encrypt_method(self) -> AuditMeasurement:
        """LNX-CIS-5.4.1.1: Weryfikacja silnego algorytmu hashowania haseł (SHA512/YESCRYPT)."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        defs_path = Path("/etc/login.defs")
        try:
            if not defs_path.exists():
                return AuditMeasurement(
                    check_id="LNX-CIS-5.4.1.1",
                    category="Password & Account Policies",
                    title="Ensure password hashing algorithm is SHA-512 or YESCRYPT",
                    collector_type="linux_login_defs",
                    target="/etc/login.defs",
                    raw_value={"value": None, "file_exists": False},
                    collected_at=now,
                    status="NOT_APPLICABLE",
                )
            val = None
            for raw_line in defs_path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                match = re.match(r"^ENCRYPT_METHOD\s+(\S+)", line, re.IGNORECASE)
                if match:
                    val = match.group(1).upper()
                    break
            return AuditMeasurement(
                check_id="LNX-CIS-5.4.1.1",
                category="Password & Account Policies",
                title="Ensure password hashing algorithm is SHA-512 or YESCRYPT",
                collector_type="linux_login_defs",
                target="/etc/login.defs::ENCRYPT_METHOD",
                raw_value={"value": val},
                collected_at=now,
                status="COLLECTED",
            )
        except Exception as exc:
            return AuditMeasurement(
                check_id="LNX-CIS-5.4.1.1",
                category="Password & Account Policies",
                title="Ensure password hashing algorithm is SHA-512 or YESCRYPT",
                collector_type="linux_login_defs",
                target="/etc/login.defs::ENCRYPT_METHOD",
                raw_value=None,
                collected_at=now,
                status="ERROR",
                error_message=str(exc),
            )

    def _collect_linux_sshd_password_auth(self) -> AuditMeasurement:
        """LNX-CIS-5.2.10: Weryfikacja wyłączenia uwierzytelniania hasłem w SSH."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        sshd_path = Path("/etc/ssh/sshd_config")
        try:
            if not sshd_path.exists():
                return AuditMeasurement(
                    check_id="LNX-CIS-5.2.10",
                    category="SSH Hardening",
                    title="Ensure SSH password authentication is disabled",
                    collector_type="linux_sshd_effective_config",
                    target="/etc/ssh/sshd_config",
                    raw_value={"directive": "PasswordAuthentication", "value": None, "file_exists": False},
                    collected_at=now,
                    status="NOT_APPLICABLE",
                )
            directive_val = "yes"
            for raw_line in sshd_path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                match = re.match(r"^PasswordAuthentication\s+(\S+)", line, re.IGNORECASE)
                if match:
                    directive_val = match.group(1).lower()
                    break
            return AuditMeasurement(
                check_id="LNX-CIS-5.2.10",
                category="SSH Hardening",
                title="Ensure SSH password authentication is disabled",
                collector_type="linux_sshd_effective_config",
                target="/etc/ssh/sshd_config::PasswordAuthentication",
                raw_value={"value": directive_val},
                collected_at=now,
                status="COLLECTED",
            )
        except Exception as exc:
            return AuditMeasurement(
                check_id="LNX-CIS-5.2.10",
                category="SSH Hardening",
                title="Ensure SSH password authentication is disabled",
                collector_type="linux_sshd_effective_config",
                target="/etc/ssh/sshd_config::PasswordAuthentication",
                raw_value=None,
                collected_at=now,
                status="ERROR",
                error_message=str(exc),
            )

    def _collect_linux_suid_dumpable(self) -> AuditMeasurement:
        """LNX-CIS-1.7.1: Weryfikacja blokady zrzutów pamięci programów SUID (fs.suid_dumpable = 0)."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        p = Path("/proc/sys/fs/suid_dumpable")
        try:
            val = int(p.read_text(encoding="ascii").strip())
            return AuditMeasurement(
                check_id="LNX-CIS-1.7.1",
                category="Kernel Memory Protection",
                title="Ensure core dumps of SUID programs are restricted (fs.suid_dumpable = 0)",
                collector_type="linux_proc_sysctl",
                target="fs.suid_dumpable",
                raw_value={"value": val},
                collected_at=now,
                status="COLLECTED",
            )
        except Exception as exc:
            return AuditMeasurement(
                check_id="LNX-CIS-1.7.1",
                category="Kernel Memory Protection",
                title="Ensure core dumps of SUID programs are restricted (fs.suid_dumpable = 0)",
                collector_type="linux_proc_sysctl",
                target="fs.suid_dumpable",
                raw_value=None,
                collected_at=now,
                status="ERROR",
                error_message=str(exc),
            )

    def _collect_linux_crontab_permissions(self) -> AuditMeasurement:
        """LNX-CIS-5.1.1: Weryfikacja uprawnień i właściciela pliku /etc/crontab (0600 root:root)."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        p = Path("/etc/crontab")
        try:
            if not p.exists():
                return AuditMeasurement(
                    check_id="LNX-CIS-5.1.1",
                    category="Filesystem Integrity & Permissions",
                    title="Ensure permissions on /etc/crontab are configured (0600 root:root)",
                    collector_type="linux_file_stat",
                    target="/etc/crontab",
                    raw_value={"file_exists": False},
                    collected_at=now,
                    status="NOT_APPLICABLE",
                )
            import grp
            import pwd
            st = p.stat()
            mode_octal = oct(st.st_mode & 0o777)[2:].zfill(4)
            owner_name = pwd.getpwuid(st.st_uid).pw_name
            group_name = grp.getgrgid(st.st_gid).gr_name
            return AuditMeasurement(
                check_id="LNX-CIS-5.1.1",
                category="Filesystem Integrity & Permissions",
                title="Ensure permissions on /etc/crontab are configured (0600 root:root)",
                collector_type="linux_file_stat",
                target="/etc/crontab",
                raw_value={
                    "uid": st.st_uid,
                    "gid": st.st_gid,
                    "owner": owner_name,
                    "group": group_name,
                    "mode_octal": mode_octal,
                },
                collected_at=now,
                status="COLLECTED",
            )
        except Exception as exc:
            return AuditMeasurement(
                check_id="LNX-CIS-5.1.1",
                category="Filesystem Integrity & Permissions",
                title="Ensure permissions on /etc/crontab are configured (0600 root:root)",
                collector_type="linux_file_stat",
                target="/etc/crontab",
                raw_value=None,
                collected_at=now,
                status="ERROR",
                error_message=str(exc),
            )

    def _collect_linux_icmp_echo_ignore_broadcasts(self) -> AuditMeasurement:
        """LNX-CIS-3.2.2: Ochrona przed atakami Smurf (icmp_echo_ignore_broadcasts = 1)."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        p = Path("/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts")
        try:
            val = int(p.read_text(encoding="ascii").strip())
            return AuditMeasurement(
                check_id="LNX-CIS-3.2.2",
                category="Kernel Network Hardening",
                title="Ensure ICMP broadcast echo requests are ignored (Smurf attack protection)",
                collector_type="linux_proc_sysctl",
                target="net.ipv4.icmp_echo_ignore_broadcasts",
                raw_value={"value": val},
                collected_at=now,
                status="COLLECTED",
            )
        except Exception as exc:
            return AuditMeasurement(
                check_id="LNX-CIS-3.2.2",
                category="Kernel Network Hardening",
                title="Ensure ICMP broadcast echo requests are ignored (Smurf attack protection)",
                collector_type="linux_proc_sysctl",
                target="net.ipv4.icmp_echo_ignore_broadcasts",
                raw_value=None,
                collected_at=now,
                status="ERROR",
                error_message=str(exc),
            )

    def _collect_linux_log_martians(self) -> AuditMeasurement:
        """LNX-CIS-3.2.4: Weryfikacja logowania podejrzanych pakietów Martian (log_martians = 1)."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        keys = {
            "net.ipv4.conf.all.log_martians": Path("/proc/sys/net/ipv4/conf/all/log_martians"),
            "net.ipv4.conf.default.log_martians": Path("/proc/sys/net/ipv4/conf/default/log_martians"),
        }
        try:
            vals = {k: int(p.read_text(encoding="ascii").strip()) for k, p in keys.items()}
            return AuditMeasurement(
                check_id="LNX-CIS-3.2.4",
                category="Kernel Network Hardening",
                title="Ensure suspicious packets (Martians) are logged",
                collector_type="linux_proc_sysctl",
                target="net.ipv4.conf.*.log_martians",
                raw_value={"values": vals},
                collected_at=now,
                status="COLLECTED",
            )
        except Exception as exc:
            return AuditMeasurement(
                check_id="LNX-CIS-3.2.4",
                category="Kernel Network Hardening",
                title="Ensure suspicious packets (Martians) are logged",
                collector_type="linux_proc_sysctl",
                target="net.ipv4.conf.*.log_martians",
                raw_value=None,
                collected_at=now,
                status="ERROR",
                error_message=str(exc),
            )

    def _collect_linux_login_defs_umask(self) -> AuditMeasurement:
        """LNX-CIS-5.4.4: Weryfikacja domyślnej maski tworzenia plików umask 027."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        defs_path = Path("/etc/login.defs")
        try:
            if not defs_path.exists():
                return AuditMeasurement(
                    check_id="LNX-CIS-5.4.4",
                    category="Filesystem Integrity & Permissions",
                    title="Ensure default user umask is 027 or more restrictive",
                    collector_type="linux_login_defs",
                    target="/etc/login.defs",
                    raw_value={"value": None, "file_exists": False},
                    collected_at=now,
                    status="NOT_APPLICABLE",
                )
            val = None
            for raw_line in defs_path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                match = re.match(r"^UMASK\s+(\S+)", line, re.IGNORECASE)
                if match:
                    val = match.group(1).strip()
                    break
            return AuditMeasurement(
                check_id="LNX-CIS-5.4.4",
                category="Filesystem Integrity & Permissions",
                title="Ensure default user umask is 027 or more restrictive",
                collector_type="linux_login_defs",
                target="/etc/login.defs::UMASK",
                raw_value={"value": val},
                collected_at=now,
                status="COLLECTED",
            )
        except Exception as exc:
            return AuditMeasurement(
                check_id="LNX-CIS-5.4.4",
                category="Filesystem Integrity & Permissions",
                title="Ensure default user umask is 027 or more restrictive",
                collector_type="linux_login_defs",
                target="/etc/login.defs::UMASK",
                raw_value=None,
                collected_at=now,
                status="ERROR",
                error_message=str(exc),
            )


# =====================================================================
# KLIENT KOMUNIKACYJNY mTLS (ZERO-TRUST TRANSPORT)
# =====================================================================

class SecureAuditTransport:
    """
    Zero-Dependency Transport (100% Python Standard Library: urllib.request + ssl).
    Nie wymaga instalacji żadnych zewnętrznych bibliotek (brak pip install requests)!
    Obsługuje TLS 1.3 / mTLS (certyfikat kliencki X.509) oraz podpis HMAC-SHA256.
    """

    def __init__(
        self,
        server_base_url: str,
        ca_cert_path: Optional[str] = None,
        client_cert_path: Optional[str] = None,
        client_key_path: Optional[str] = None,
        hmac_secret: Optional[str] = None,
        timeout_seconds: int = 15,
    ) -> None:
        self.server_base_url = server_base_url.rstrip("/")
        self.ca_cert_path = ca_cert_path
        self.client_cert_path = client_cert_path
        self.client_key_path = client_key_path
        self.hmac_secret = hmac_secret
        self.timeout_seconds = timeout_seconds
        self.ssl_context = self._build_ssl_context()

    def _build_ssl_context(self) -> Optional[ Any ]:
        import ssl

        if not self.server_base_url.lower().startswith("https://"):
            return None

        if self.ca_cert_path and Path(self.ca_cert_path).exists():
            ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.ca_cert_path)
        else:
            ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

        if (
            self.client_cert_path
            and self.client_key_path
            and Path(self.client_cert_path).exists()
            and Path(self.client_key_path).exists()
        ):
            ctx.load_cert_chain(certfile=self.client_cert_path, keyfile=self.client_key_path)

        return ctx

    def _compute_signature(self, payload_bytes: bytes, timestamp: str, nonce: str) -> str:
        if not self.hmac_secret:
            return ""
        signing_input = f"{timestamp}.{nonce}.".encode("utf-8") + payload_bytes
        return hmac.new(
            self.hmac_secret.encode("utf-8"),
            signing_input,
            hashlib.sha256,
        ).hexdigest()

    def send_audit_report(self, report: AuditReportPayload) -> Dict[str, Any]:
        endpoint = f"{self.server_base_url}/api/v1/audit"
        payload_dict = asdict(report)

        payload_bytes = json.dumps(
            payload_dict,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        request_nonce = str(uuid.uuid4())
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": f"SystemAuditor-Agent/2.0 ({report.os_family}; {report.architecture})",
            "X-Agent-ID": report.agent_id,
            "X-Request-Timestamp": report.timestamp_utc,
            "X-Request-Nonce": request_nonce,
            "X-Client-Cert-CN": report.agent_id,
        }

        signature = self._compute_signature(payload_bytes, report.timestamp_utc, request_nonce)
        if signature:
            headers["X-Payload-Signature"] = f"sha256={signature}"

        logger.info(
            "Wysyłanie raportu audytu [report_id=%s] do %s (%d pomiarów)...",
            report.report_id,
            endpoint,
            len(report.measurements),
        )

        req = urllib.request.Request(
            url=endpoint,
            data=payload_bytes,
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds, context=self.ssl_context) as resp:
                resp_body = resp.read().decode("utf-8")
                logger.info("Raport zaakceptowany pomyślnie (HTTP %d).", resp.status)
                return json.loads(resp_body)
        except urllib.error.HTTPError as http_err:
            err_body = http_err.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"Serwer odrzucił raport audytu: HTTP {http_err.code} - {err_body}"
            ) from http_err


# =====================================================================
# GŁÓWNY PUNKT WEJŚCIA AGENTA
# =====================================================================

def build_audit_report(
    agent_id: str, policy_version: str, full_suite: bool = True
) -> AuditReportPayload:
    """Zbiera parametry z systemu i buduje kompletny obiekt raportu."""
    collector = OSParameterCollector()
    measurements = collector.collect_security_parameters(full_suite=full_suite)

    return AuditReportPayload(
        schema_version="1.0",
        report_id=str(uuid.uuid4()),
        agent_id=agent_id,
        hostname=socket.getfqdn(),
        os_family=platform.system(),
        os_release=f"{platform.system()} {platform.release()} ({platform.version()})",
        architecture=platform.machine(),
        is_elevated=collector.check_elevated_privileges(),
        timestamp_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        policy_version=policy_version,
        boot_id=collector.get_system_boot_id(),
        measurements=[asdict(m) for m in measurements],
    )


def enroll_agent_with_server(server_url: str, enrollment_token: str, agent_id: str, certs_dir: Path) -> bool:
    """
    Automatyczna rejestracja (Zero-Touch Enrollment) na nowym serwerze.
    Jeśli dostępny jest pakiet `cryptography`, generuje lokalnie klucz ECDSA P-256 i CSR PKCS#10.
    Jeśli na serwerze docelowym jest tylko czysty Python (bez pip), wysyła sam raport HMAC bez błędu.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
    except ImportError:
        logger.info(
            "Tryb Zero-Dependency (brak zewnętrznego pakietu 'cryptography'): "
            "pomijam generowanie CSR X.509 i używam uwierzytelniania HMAC-SHA256."
        )
        return False

    certs_dir.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
                    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, socket.getfqdn()),
                ]
            )
        )
        .sign(key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    endpoint = f"{server_url.rstrip('/')}/api/v1/register"
    req_bytes = json.dumps(
        {
            "enrollment_token": enrollment_token,
            "csr_pem": csr_pem,
            "agent_id": agent_id,
            "hostname": socket.getfqdn(),
            "os_family": platform.system(),
            "os_release": f"{platform.system()} {platform.release()}",
            "architecture": platform.machine(),
        }
    ).encode("utf-8")

    req = urllib.request.Request(
        url=endpoint,
        data=req_bytes,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read().decode("utf-8"))

    (certs_dir / "agent.key").write_text(key_pem, encoding="utf-8")
    (certs_dir / "agent.crt").write_text(data["client_cert_pem"], encoding="utf-8")
    (certs_dir / "root-ca.crt").write_text(data["ca_chain_pem"], encoding="utf-8")
    (certs_dir / "policy-ed25519.pub").write_text(data["ed25519_policy_pubkey_pem"], encoding="utf-8")

    logger.info(
        "Pomyślnie zarejestrowano Agenta! SPIFFE ID: %s, Certyfikat ważny do: %s",
        data.get("spiffe_id"),
        data.get("expires_at"),
    )
    return True


def run_agent_diagnostics(server_url: str) -> int:
    """Kompleksowa autodiagnostyka agenta z czytelnym podsumowaniem wykrytych błędów."""
    print("=" * 72)
    print(" SystemAuditor Enterprise — Autodiagnostyka Agenta Endpoint")
    print("=" * 72)

    is_elevated = OSParameterCollector.check_elevated_privileges()
    os_name = platform.system()
    print("\n[1/5] Środowisko wykonawcze:")
    print(f"  • System OS:       {os_name} {platform.release()} ({platform.architecture()[0]})")
    print(f"  • Wersja Python:   {sys.version.split()[0]} ({sys.executable})")
    print(f"  • Hostname / FQDN: {socket.getfqdn()}")
    print(f"  • Uprawnienia:     {'ADMINISTRATOR / ROOT (OK)' if is_elevated else 'ZWYKŁY UŻYTKOWNIK (OSTRZEŻENIE)'}")

    if not is_elevated:
        if os_name.lower() == "windows":
            print("    ⚠️ UWAGA: Agent nie ma uprawnień Administratora. Niektóre kontrole (BitLocker, NetUser) mogą zwrócić błąd.")
            print("    💡 Sugestia: Uruchom terminal PowerShell jako Administrator.")
        else:
            print("    ⚠️ UWAGA: Agent nie działa jako root (UID != 0). Odczyt /etc/sudoers i /etc/shadow będzie zablokowany.")
            print("    💡 Sugestia: Uruchom agenta poleceniem: sudo python3 agent_poc.py")

    print("\n[2/5] Obsługa kryptografii:")
    try:
        from cryptography import x509
        print("  • Pakiet 'cryptography': ZAINSTALOWANY (obsługuje mTLS X.509 i CSR ECDSA P-256)")
    except ImportError:
        print("  • Pakiet 'cryptography': BRAK (Tryb Zero-Dependency — agent używa natywnego HMAC-SHA256)")

    print(f"\n[3/5] Połączenie z Serwerem Centralnym ({server_url}):")
    health_url = f"{server_url.rstrip('/')}/health"
    try:
        req = urllib.request.Request(health_url, headers={"User-Agent": "SystemAuditor-Diagnostics"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            print(f"  • Status HTTP:     {resp.status} OK")
            print(f"  • Stan backendu:   {data.get('status')} (Katalog reguł: {data.get('rules_catalog', {}).get('total_rules')} reguł)")
    except urllib.error.HTTPError as he:
        print(f"  • Status HTTP:     Błąd {he.code} ({he.reason})")
    except Exception as ce:
        print(f"  ❌ BŁĄD POŁĄCZENIA: {ce}")
        print("    💡 Przyczyna: Serwer centralny nie jest uruchomiony, firewall blokuje port lub podano zły adres IP.")
        print(f"    💡 Sprawdź: curl -I {server_url}/health lub uruchom uvicorn z flagą --host 0.0.0.0")

    print("\n[4/5] Próba odczytu parametrów bezpieczeństwa OS (CIS):")
    collector = OSParameterCollector()
    try:
        measurements = collector.collect_security_parameters(full_suite=True)
        ok_count = sum(1 for m in measurements if m.status == "COLLECTED")
        err_count = sum(1 for m in measurements if m.status == "ERROR")
        na_count = sum(1 for m in measurements if m.status == "NOT_APPLICABLE")

        print(f"  • Wykonano kontroli: {len(measurements)}")
        print(f"  • Pobrane pomyślnie: {ok_count}")
        print(f"  • Nie dotyczy (N/A): {na_count}")
        print(f"  • Błędy odczytu:    {err_count}")

        if err_count > 0:
            print("\n  ❌ Szczegóły błędów poszczególnych kontroli:")
            for m in measurements:
                if m.status == "ERROR":
                    print(f"    - [{m.check_id}] {m.title}: {m.error_message}")
        else:
            print("  • Wszystkie kolektory wykonały się bez błędów krytycznych!")
    except Exception as exc:
        print(f"  ❌ KRYTYCZNY BŁĄD KOLEKTORA: {exc}")

    print("\n" + "=" * 72)
    print(" Koniec diagnostyki.")
    print("=" * 72)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="SystemAuditor Enterprise Endpoint Agent")
    parser.add_argument(
        "--server",
        default=os.environ.get("AUDITOR_SERVER_URL", "http://127.0.0.1:8000"),
        help="Adres URL Serwera Centralnego SystemAuditor",
    )
    parser.add_argument(
        "--agent-id",
        default=os.environ.get("AUDITOR_AGENT_ID", f"agt-{socket.gethostname().lower()}"),
        help="Identyfikator UUID/Nazwa Agenta",
    )
    parser.add_argument(
        "--enroll",
        action="store_true",
        help="Wykonaj automatyczną rejestrację CSR PKCS#10 (/api/v1/register) przed audytem",
    )
    parser.add_argument(
        "--enrollment-token",
        default=os.environ.get("AUDITOR_ENROLLMENT_TOKEN", "enr-token-2026-enterprise-bootstrap"),
        help="Jednorazowy token rejestracyjny Enrollment Token",
    )
    parser.add_argument(
        "--diagnose",
        action="store_true",
        help="Uruchom tryb pełnej autodiagnostyki środowiska i połączenia (wypisuje błędy na ekran)",
    )
    parser.add_argument(
        "--daemon",
        action="store_true",
        help="Działaj w trybie ciągłej usługi w tle (cykliczny Heartbeat + Audyt CIS)",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=300,
        help="Interwał pomiędzy automatycznymi audytami w trybie --daemon (w sekundach, domyślnie 300s)",
    )
    parser.add_argument(
        "--two-checks-only",
        action="store_true",
        help="Pobierz wyłącznie 2 podstawowe parametry PoC zamiast pełnego zestawu reguł CIS",
    )
    args = parser.parse_args()

    if args.diagnose:
        return run_agent_diagnostics(args.server)

    policy_version = os.environ.get("AUDITOR_POLICY_VERSION", "2026.10.2")
    base_dir = Path(__file__).resolve().parent
    certs_dir = base_dir / "data" / "certs"

    ca_cert = os.environ.get("AUDITOR_CA_CERT", str(certs_dir / "root-ca.crt"))
    client_cert = os.environ.get("AUDITOR_CLIENT_CERT", str(certs_dir / "agent.crt"))
    client_key = os.environ.get("AUDITOR_CLIENT_KEY", str(certs_dir / "agent.key"))
    hmac_secret = os.environ.get("AUDITOR_HMAC_SECRET", "super-secret-agent-signing-key")

    if args.enroll:
        enroll_agent_with_server(args.server, args.enrollment_token, args.agent_id, certs_dir)

    transport = SecureAuditTransport(
        server_base_url=args.server,
        ca_cert_path=ca_cert,
        client_cert_path=client_cert,
        client_key_path=client_key,
        hmac_secret=hmac_secret,
    )

    import time

    while True:
        report = build_audit_report(
            agent_id=args.agent_id,
            policy_version=policy_version,
            full_suite=not args.two_checks_only,
        )

        formatted_json = json.dumps(asdict(report), indent=2, ensure_ascii=False)
        logger.info("Wygenerowano pakiet JSON audytu (%d pomiarów):\n%s", len(report.measurements), formatted_json)

        try:
            server_resp = transport.send_audit_report(report)
            logger.info(
                "Odpowiedź Serwera Centralnego:\n%s",
                json.dumps(server_resp, indent=2, ensure_ascii=False),
            )
        except Exception as exc:
            logger.warning(
                "Nie udało się przesłać raportu do %s (%s).",
                args.server,
                exc,
            )

        if not args.daemon:
            break

        logger.info("Tryb usługi (--daemon): kolejny audyt za %d sekund...", args.interval)
        time.sleep(args.interval)

    return 0


if __name__ == "__main__":
    sys.exit(main())
