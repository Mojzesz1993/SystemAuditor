"""
SystemAuditor Enterprise — Zestaw Testów End-to-End (E2E) i Weryfikacja Architektury
====================================================================================
Testuje cały potok rozproszonego systemu audytu:
1. Inicjalizację Zero-Trust PKI (Root CA, CSR PKCS#10, podpisy Ed25519 polityki).
2. Rejestrację nowego Agenta (`/api/v1/register`) oraz odbiór certyfikatu X.509 mTLS.
3. Pobranie podpisanego katalogu reguł (`/api/v1/policies/current`) i weryfikację podpisu Ed25519.
4. Natywne zebranie 8 parametrów bezpieczeństwa z bieżącego systemu Windows (`agent_poc.py`)
   i przesłanie ich z podpisem HMAC-SHA256 na `/api/v1/audit`.
5. Symulację 4 klas ataków na Serwer Centralny (Replay Attack, Cert Spoofing, All-Green Lie, SQLi/XSS)
   i potwierdzenie zadziałania mechanizmów obronnych Anti-Poisoning.
"""

import hashlib
import hmac
import json
import sys
import uuid
from dataclasses import asdict

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from agent_poc import build_audit_report
from backend.main import BOOTSTRAP_ENROLLMENT_TOKEN, HMAC_SHARED_SECRET, app, pki_manager


def run_all_verifications() -> None:
    with TestClient(app) as client:
        print("=" * 78)
        print("1. TEST ZERO-TRUST PKI & REJESTRACJA CSR (/api/v1/register)")
        print("=" * 78)
        agent_key = ec.generate_private_key(ec.SECP256R1())
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agt-e2e-test-node")]))
            .sign(agent_key, hashes.SHA256())
        )
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")

        reg_resp = client.post(
            "/api/v1/register",
            json={
                "enrollment_token": BOOTSTRAP_ENROLLMENT_TOKEN,
                "csr_pem": csr_pem,
                "agent_id": "agt-e2e-test-node",
                "hostname": "sec-test-node.corp.internal",
                "os_family": "Windows",
                "os_release": "Windows 11 Enterprise",
                "architecture": "AMD64",
            },
        )
        assert reg_resp.status_code == 201, reg_resp.text
        reg_data = reg_resp.json()
        print(f"[OK] Wystawiono certyfikat X.509 mTLS: serial={reg_data['cert_serial']}, SPIFFE={reg_data['spiffe_id']}")

        print("\n" + "=" * 78)
        print("2. TEST PODPISANEJ POLITYKI CIS (Ed25519 Signature Verification)")
        print("=" * 78)
        pol_resp = client.get("/api/v1/policies/current?os_family=windows")
        assert pol_resp.status_code == 200
        pol_data = pol_resp.json()
        sig_hex = pol_data["policy_metadata"]["signature_ed25519"]
        is_sig_valid = pki_manager.verify_policy_signature(pol_data["rules"], sig_hex)
        assert is_sig_valid is True
        print(
            f"[OK] Pobrano {len(pol_data['rules'])} reguł CIS dla Windows. "
            f"Weryfikacja podpisu kryptograficznego Ed25519: VALID ({sig_hex[:32]}...)"
        )

        print("\n" + "=" * 78)
        print("3. TEST NATYWNEGO AUDYTU LIVE OS + WYSYŁKI Z HMAC-SHA256 (/api/v1/audit)")
        print("=" * 78)
        live_report = build_audit_report(
            agent_id="agt-e2e-test-node",
            policy_version=pol_data["policy_metadata"]["version"],
            full_suite=True,
        )
        payload_bytes = json.dumps(
            asdict(live_report), ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        nonce = str(uuid.uuid4())
        sig = hmac.new(
            HMAC_SHARED_SECRET.encode("utf-8"),
            f"{live_report.timestamp_utc}.{nonce}.".encode("utf-8") + payload_bytes,
            hashlib.sha256,
        ).hexdigest()

        audit_resp = client.post(
            "/api/v1/audit",
            content=payload_bytes,
            headers={
                "Content-Type": "application/json",
                "X-Agent-ID": live_report.agent_id,
                "X-Request-Timestamp": live_report.timestamp_utc,
                "X-Request-Nonce": nonce,
                "X-Payload-Signature": f"sha256={sig}",
                "X-Client-Cert-CN": live_report.agent_id,
            },
        )
        assert audit_resp.status_code == 202, audit_resp.text
        audit_data = audit_resp.json()
        print(
            f"[OK] Przetworzono {audit_data['evaluated_rules']} natywnych reguł CIS z lokalnego systemu Windows!"
        )
        print(
            f"     Wynik Security Posture: {audit_data['posture_score']}% | "
            f"PASS={audit_data['counts']['PASS']}, FAIL={audit_data['counts']['FAIL']}"
        )

        print("\n" + "=" * 78)
        print("4. TEST OCHRONY ANTI-REPLAY (Powtórne wysłanie tego samego X-Request-Nonce)")
        print("=" * 78)
        replay_resp = client.post(
            "/api/v1/audit",
            content=payload_bytes,
            headers={
                "Content-Type": "application/json",
                "X-Agent-ID": live_report.agent_id,
                "X-Request-Timestamp": live_report.timestamp_utc,
                "X-Request-Nonce": nonce,  # Ten sam Nonce!
                "X-Payload-Signature": f"sha256={sig}",
                "X-Client-Cert-CN": live_report.agent_id,
            },
        )
        assert replay_resp.status_code == 409, replay_resp.text
        print(f"[OK] Atak Replay zablokowany (HTTP {replay_resp.status_code}): {replay_resp.json()['detail']}")

        print("\n" + "=" * 78)
        print("5. TEST DETEKTORA ZATRUCIA BAZY (Database Poisoning: Spoofing & SQLi/XSS)")
        print("=" * 78)
        for scenario in ("spoofing", "all_green_lie", "sql_xss_injection"):
            sim_resp = client.post(
                "/api/v1/security/simulate-attack",
                json={"scenario": scenario, "target_agent_id": "agt-win-legacy-erp04"},
            )
            assert sim_resp.status_code == 200
            sim_data = sim_resp.json()
            assert sim_data["quarantined"] is True
            print(
                f"[OK] Scenariusz '{scenario}' -> Kwarantanna={sim_data['quarantined']} "
                f"(Ryzyko anomalii: {sim_data['anomaly_risk_score']}/100)"
            )
            for finding in sim_data["findings"]:
                print(f"     -> Wykryto: {finding}")

        print("\n" + "=" * 78)
        print("WSZYSTKIE TESTY ARCHITEKTURY I BEZPIECZEŃSTWA ZAKOŃCZONE SUKCESEM!")
        print("=" * 78)


if __name__ == "__main__":
    run_all_verifications()
