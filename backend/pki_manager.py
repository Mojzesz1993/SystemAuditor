"""
SystemAuditor Enterprise — Moduł Zero-Trust PKI (X.509 mTLS + Ed25519 Policy Signing)
======================================================================================
Odpowiada za:
1. Automatyczne tworzenie wewnętrznego Root CA (ECDSA P-256) oraz certyfikatu serwera TLS.
2. Podpisywanie żądań CSR (PKCS#10) przesyłanych przez nowe lub odnawiające certyfikat Agenty
   (krótkotrwałe certyfikaty X.509 z SAN URI spiffe://systemauditor.corp/agent/<agent_id>).
3. Generowanie i weryfikację podpisów kryptograficznych Ed25519 dla katalogu reguł YAML/JSON
   (ochrona przed wstrzyknięciem fałszywych polityk).
4. Rejestr unieważnionych certyfikatów (CRL / In-Memory Revocation Set).
"""

import datetime
import hashlib
import json
from pathlib import Path
from typing import Dict, Optional, Set, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


class ZeroTrustPKIManager:
    """Zarządza cyklem życia certyfikatów X.509 mTLS oraz podpisami Ed25519 polityk."""

    def __init__(self, certs_dir: Path) -> None:
        self.certs_dir = certs_dir
        self.certs_dir.mkdir(parents=True, exist_ok=True)

        self.ca_key_path = self.certs_dir / "root-ca.key"
        self.ca_cert_path = self.certs_dir / "root-ca.crt"
        self.server_key_path = self.certs_dir / "server.key"
        self.server_cert_path = self.certs_dir / "server.crt"
        self.ed25519_priv_path = self.certs_dir / "policy-ed25519.key"
        self.ed25519_pub_path = self.certs_dir / "policy-ed25519.pub"
        self.default_agent_key_path = self.certs_dir / "agent.key"
        self.default_agent_cert_path = self.certs_dir / "agent.crt"

        self.revoked_serials: Set[int] = set()
        self.enrollment_tokens: Dict[str, dict] = {}

        self._ca_key: Optional[ec.EllipticCurvePrivateKey] = None
        self._ca_cert: Optional[x509.Certificate] = None
        self._ed25519_priv: Optional[ed25519.Ed25519PrivateKey] = None
        self._ed25519_pub: Optional[ed25519.Ed25519PublicKey] = None

        self.ensure_infrastructure_bootstrapped()

    def ensure_infrastructure_bootstrapped(self) -> None:
        """Inicjalizuje klucze CA, certyfikat serwera, parę Ed25519 oraz domyślny certyfikat Agenta."""
        if not self.ca_key_path.exists() or not self.ca_cert_path.exists():
            self._generate_root_ca()
        else:
            self._load_root_ca()

        if not self.server_key_path.exists() or not self.server_cert_path.exists():
            self._generate_server_cert()

        if not self.ed25519_priv_path.exists() or not self.ed25519_pub_path.exists():
            self._generate_ed25519_keys()
        else:
            self._load_ed25519_keys()

        # Wygeneruj domyślny certyfikat dla lokalnego Agenta PoC, aby mTLS działał od razu
        if not self.default_agent_key_path.exists() or not self.default_agent_cert_path.exists():
            self.issue_agent_bundle(
                agent_id="agt-0192f8a4-7c9b-7000-8000-1a2b3c4d5e6f",
                hostname="local-workstation",
                ttl_days=7,
                save_to_default=True,
            )

    def _generate_root_ca(self) -> None:
        """Tworzy prywatny urząd certyfikacji Root CA (ECDSA P-256)."""
        ca_key = ec.generate_private_key(ec.SECP256R1())
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "PL"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SystemAuditor Security Corp"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Zero-Trust PKI Root CA"),
                x509.NameAttribute(NameOID.COMMON_NAME, "SystemAuditor Internal Root CA G1"),
            ]
        )
        now = datetime.datetime.now(datetime.timezone.utc)
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256())
        )

        self.ca_key_path.write_bytes(
            ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        self.ca_cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
        self._ca_key = ca_key
        self._ca_cert = ca_cert

    def _load_root_ca(self) -> None:
        self._ca_key = serialization.load_pem_private_key(
            self.ca_key_path.read_bytes(), password=None
        )  # type: ignore[assignment]
        self._ca_cert = x509.load_pem_x509_certificate(self.ca_cert_path.read_bytes())

    def _generate_server_cert(self) -> None:
        """Generuje certyfikat TLS dla Serwera Centralnego (localhost / 127.0.0.1 / auditor-core)."""
        assert self._ca_key is not None and self._ca_cert is not None
        srv_key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "PL"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SystemAuditor Security Corp"),
                x509.NameAttribute(NameOID.COMMON_NAME, "auditor-core.internal.corp"),
            ]
        )
        now = datetime.datetime.now(datetime.timezone.utc)
        import ipaddress

        srv_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._ca_cert.subject)
            .public_key(srv_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName("localhost"),
                        x509.DNSName("auditor-core.internal.corp"),
                        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                    ]
                ),
                critical=False,
            )
            .sign(self._ca_key, hashes.SHA256())
        )

        self.server_key_path.write_bytes(
            srv_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        self.server_cert_path.write_bytes(srv_cert.public_bytes(serialization.Encoding.PEM))

    def _generate_ed25519_keys(self) -> None:
        """Generuje parę kluczy Ed25519 do kryptograficznego podpisywania katalogu reguł."""
        priv = ed25519.Ed25519PrivateKey.generate()
        pub = priv.public_key()
        self.ed25519_priv_path.write_bytes(
            priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        self.ed25519_pub_path.write_bytes(
            pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        self._ed25519_priv = priv
        self._ed25519_pub = pub

    def _load_ed25519_keys(self) -> None:
        self._ed25519_priv = serialization.load_pem_private_key(
            self.ed25519_priv_path.read_bytes(), password=None
        )  # type: ignore[assignment]
        self._ed25519_pub = serialization.load_pem_public_key(
            self.ed25519_pub_path.read_bytes()
        )  # type: ignore[assignment]

    def sign_csr(self, csr_pem: str, agent_id: str, ttl_days: int = 7) -> Tuple[str, int, str]:
        """
        Weryfikuje podpis na żądaniu CSR (PKCS#10) i wystawia krótkotrwały certyfikat X.509
        z rozszerzeniem ClientAuth oraz SPIFFE URI.
        Zwraca (cert_pem, serial_number, expires_at_iso).
        """
        assert self._ca_key is not None and self._ca_cert is not None
        csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"))
        if not csr.is_signature_valid:
            raise ValueError("Podpis kryptograficzny na żądaniu CSR jest nieprawidłowy!")

        now = datetime.datetime.now(datetime.timezone.utc)
        expires_at = now + datetime.timedelta(days=ttl_days)
        serial_num = x509.random_serial_number()

        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "PL"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SystemAuditor Managed Endpoint"),
                x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
            ]
        )

        spiffe_uri = f"spiffe://systemauditor.corp/agent/{agent_id}"
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(serial_num)
            .not_valid_before(now - datetime.timedelta(minutes=2))
            .not_valid_after(expires_at)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=True,
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.UniformResourceIdentifier(spiffe_uri),
                        x509.DNSName(agent_id),
                    ]
                ),
                critical=False,
            )
            .sign(self._ca_key, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        return cert_pem, serial_num, expires_at.isoformat()

    def issue_agent_bundle(
        self,
        agent_id: str,
        hostname: str,
        ttl_days: int = 7,
        save_to_default: bool = False,
    ) -> Dict[str, str]:
        """Pomocnicza metoda tworząca klucz + CSR + podpisany certyfikat X.509 dla Agenta."""
        key = ec.generate_private_key(ec.SECP256R1())
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
                        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, hostname),
                    ]
                )
            )
            .sign(key, hashes.SHA256())
        )
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        cert_pem, serial_num, expires_at = self.sign_csr(csr_pem, agent_id=agent_id, ttl_days=ttl_days)
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        if save_to_default:
            self.default_agent_key_path.write_text(key_pem, encoding="utf-8")
            self.default_agent_cert_path.write_text(cert_pem, encoding="utf-8")

        return {
            "agent_id": agent_id,
            "client_cert_pem": cert_pem,
            "client_key_pem": key_pem,
            "ca_cert_pem": self.ca_cert_path.read_text(encoding="utf-8"),
            "serial_number": hex(serial_num),
            "expires_at": expires_at,
        }

    def sign_policy_document(self, rules_list: list) -> str:
        """Podpisuje kanoniczną reprezentację JSON listy reguł kluczem prywatnym Ed25519."""
        assert self._ed25519_priv is not None
        canonical_bytes = json.dumps(rules_list, sort_keys=True, separators=(",", ":")).encode("utf-8")
        signature = self._ed25519_priv.sign(canonical_bytes)
        return signature.hex()

    def verify_policy_signature(self, rules_list: list, signature_hex: str) -> bool:
        """Weryfikuje podpis Ed25519 katalogu reguł."""
        assert self._ed25519_pub is not None
        try:
            canonical_bytes = json.dumps(rules_list, sort_keys=True, separators=(",", ":")).encode("utf-8")
            self._ed25519_pub.verify(bytes.fromhex(signature_hex), canonical_bytes)
            return True
        except Exception:
            return False

    def get_public_ed25519_pem(self) -> str:
        return self.ed25519_pub_path.read_text(encoding="utf-8")

    @staticmethod
    def compute_cert_fingerprint(cert_pem: str) -> str:
        cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
        return cert.fingerprint(hashes.SHA256()).hex()
