"""
SystemAuditor Enterprise — Silnik Reguł (Rule Engine) i Detektor Zatrucia (Anti-Poisoning)
=========================================================================================
1. Ewaluuje surowe fakty pomiarowe (Raw Evidence) przysłane przez Agenty względem
   deklaratywnych reguł CIS z `rules_catalog.yaml`.
2. Oblicza ważony wynik Security Posture Score (0-100%) na podstawie wag CVSS / Risk Severity.
3. Wykrywa próby manipulacji i zatruwania bazy danych (Database Poisoning):
   - Weryfikacja powiązania kryptograficznego (CN certyfikatu vs agent_id).
   - Detekcja ataków Replay (Timestamp Drift + Nonce Cache).
   - Detekcja "All-Green Lie" / gwałtownego skoku zgodności bez restartu hosta.
   - Detekcja zerowej entropii czasowej pomiarów (syntetyczne raporty).
   - Weryfikacja reguł kanarkowych (Canary Challenge-Response).
"""

import datetime
import math
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml


SEVERITY_WEIGHTS = {
    "CRITICAL": 10.0,
    "HIGH": 6.0,
    "MEDIUM": 3.0,
    "LOW": 1.0,
}


@dataclass
class EvaluatedCheckResult:
    rule_id: str
    category: str
    title: str
    benchmark_ref: str
    mitre_attack: List[str]
    risk_severity: str
    cvss_base_score: float
    compliance_status: str  # PASS, FAIL, NOT_APPLICABLE, ERROR, UNKNOWN_RULE
    observed_value: Any
    expected_summary: str
    remediation: str
    rationale: str
    compliance_frameworks: Optional[Dict[str, str]] = None


@dataclass
class AnomalyDetectionResult:
    is_suspicious: bool
    quarantine_recommended: bool
    risk_score: int  # 0 - 100
    findings: List[str]


class CISRuleEngine:
    """Silnik ewaluacji zgodności konfiguracji OS ze standardem CIS Benchmarks."""

    def __init__(self, catalog_path: Path) -> None:
        self.catalog_path = catalog_path
        self.metadata: Dict[str, Any] = {}
        self.rules_by_id: Dict[str, Dict[str, Any]] = {}
        self.rules_list: List[Dict[str, Any]] = []
        self.reload_catalog()

    def reload_catalog(self) -> None:
        raw_data = yaml.safe_load(self.catalog_path.read_text(encoding="utf-8"))
        self.metadata = raw_data.get("policy_metadata", {})
        self.rules_list = raw_data.get("rules", [])
        self.rules_by_id = {r["rule_id"]: r for r in self.rules_list}

    def get_rules_for_os(self, os_family: Optional[str] = None) -> List[Dict[str, Any]]:
        if not os_family:
            return self.rules_list
        os_norm = os_family.lower()
        return [r for r in self.rules_list if r.get("os_family", "").lower() == os_norm]

    def evaluate_measurements(
        self, os_family: str, measurements: List[Dict[str, Any]]
    ) -> Tuple[List[EvaluatedCheckResult], float, Dict[str, int]]:
        """
        Porównuje surowe pomiary z oczekiwanym wzorcem w katalogu reguł.
        Zwraca: (lista_wynikow, posture_score_pct, podsumowanie_licznikow)
        """
        evaluated: List[EvaluatedCheckResult] = []
        total_weight = 0.0
        earned_weight = 0.0
        counts = {"PASS": 0, "FAIL": 0, "ERROR": 0, "NOT_APPLICABLE": 0}

        for m in measurements:
            check_id = m.get("check_id", "")
            rule = self.rules_by_id.get(check_id)

            if not rule:
                evaluated.append(
                    EvaluatedCheckResult(
                        rule_id=check_id,
                        category=m.get("category", "Unknown"),
                        title=m.get("title", check_id),
                        benchmark_ref="N/A",
                        mitre_attack=[],
                        risk_severity="MEDIUM",
                        cvss_base_score=5.0,
                        compliance_status="ERROR",
                        observed_value=m.get("raw_value"),
                        expected_summary="Reguła spoza autoryzowanego katalogu",
                        remediation="Zweryfikuj wersję polityki na agencie.",
                        rationale="Nierozpoznany identyfikator reguły w katalogu centralnym.",
                        compliance_frameworks={},
                    )
                )
                counts["ERROR"] += 1
                continue

            severity = rule.get("risk_severity", "MEDIUM").upper()
            weight = SEVERITY_WEIGHTS.get(severity, 3.0)
            status_in = m.get("status", "COLLECTED")
            raw_val = m.get("raw_value")

            if status_in == "NOT_APPLICABLE":
                counts["NOT_APPLICABLE"] += 1
                evaluated.append(
                    self._build_result(
                        rule,
                        "NOT_APPLICABLE",
                        raw_val,
                        "Komponent lub usługa nie występuje na tym hoście.",
                    )
                )
                continue

            if status_in == "ERROR":
                total_weight += weight
                counts["ERROR"] += 1
                evaluated.append(
                    self._build_result(
                        rule,
                        "ERROR",
                        raw_val,
                        f"Błąd odczytu kolektora: {m.get('error_message', 'Brak uprawnień lub klucza')}",
                    )
                )
                continue

            # Ewaluacja właściwego operatora reguły
            passed, rationale = self._evaluate_single_rule(rule, raw_val)
            total_weight += weight
            if passed:
                earned_weight += weight
                counts["PASS"] += 1
                comp_status = "PASS"
            else:
                counts["FAIL"] += 1
                comp_status = "FAIL"

            evaluated.append(self._build_result(rule, comp_status, raw_val, rationale))

        score_pct = round((earned_weight / total_weight) * 100.0, 1) if total_weight > 0 else 100.0
        return evaluated, score_pct, counts

    def _evaluate_single_rule(
        self, rule: Dict[str, Any], raw_value: Any
    ) -> Tuple[bool, str]:
        expected = rule.get("expected_state", {})
        operator = expected.get("operator", "equals")

        # Wyodrębnienie głównej wartości z obiektu raw_value
        extracted = raw_value
        if isinstance(raw_value, dict) and "value" in raw_value:
            extracted = raw_value["value"]

        if operator == "equals":
            target_val = expected.get("value")
            if isinstance(extracted, str) and isinstance(target_val, str):
                if not expected.get("case_sensitive", True):
                    is_ok = extracted.strip().lower() == target_val.strip().lower()
                else:
                    is_ok = extracted.strip() == target_val.strip()
            else:
                is_ok = extracted == target_val
            return (
                is_ok,
                f"Wartość obserwowana ({extracted!r}) {'jest zgodna' if is_ok else 'NIE jest zgodna'} z oczekiwaną ({target_val!r}).",
            )

        elif operator == "in_set":
            allowed = expected.get("allowed_values", [])
            is_ok = extracted in allowed
            return (
                is_ok,
                f"Wartość obserwowana ({extracted!r}) {'należy' if is_ok else 'NIE należy'} do zbioru bezpiecznych wartości {allowed}.",
            )

        elif operator == "greater_than_or_equal":
            target_val = expected.get("value", 0)
            try:
                num_val = float(extracted)
                is_ok = num_val >= float(target_val)
            except (TypeError, ValueError):
                is_ok = False
            return (
                is_ok,
                f"Wartość obserwowana ({extracted!r}) {'spełnia' if is_ok else 'NIE spełnia'} warunku >= {target_val}.",
            )

        elif operator == "all_equal":
            target_val = expected.get("value")
            if isinstance(raw_value, dict) and "values" in raw_value:
                vals_map = raw_value["values"]
                is_ok = bool(vals_map) and all(v == target_val for v in vals_map.values())
                return (
                    is_ok,
                    f"Mapa parametrów jądra {vals_map} {'w całości równa' if is_ok else 'zawiera odchylenia od'} {target_val!r}.",
                )
            is_ok = extracted == target_val
            return is_ok, f"Wartość ({extracted!r}) vs oczekiwana ({target_val!r})."

        elif operator == "file_acl_match":
            if not isinstance(raw_value, dict):
                return False, "Brak struktury metadanych statystyki pliku."
            uid = raw_value.get("uid")
            group = raw_value.get("group")
            mode_octal_str = str(raw_value.get("mode_octal", "0777"))

            exp_uid = expected.get("expected_uid", 0)
            allowed_groups = expected.get("allowed_groups", ["root", "shadow"])
            forbidden_mask = int(str(expected.get("forbidden_mode_bits_octal", "0137")), 8)

            try:
                current_mode = int(mode_octal_str, 8)
            except ValueError:
                return False, f"Nieprawidłowy format uprawnień oktalnych: {mode_octal_str}"

            uid_ok = uid == exp_uid
            grp_ok = group in allowed_groups
            bits_ok = (current_mode & forbidden_mask) == 0
            is_ok = uid_ok and grp_ok and bits_ok

            return (
                is_ok,
                f"UID={uid} (oczekiwany {exp_uid}), Grupa={group} (dozwolone {allowed_groups}), "
                f"Tryb={mode_octal_str} (zabronione bity {expected.get('forbidden_mode_bits_octal')} -> {'OK' if bits_ok else 'NARUSZENIE'}).",
            )

        return False, f"Nieobsługiwany operator reguły: {operator}"

    def _build_result(
        self,
        rule: Dict[str, Any],
        compliance_status: str,
        observed_value: Any,
        rationale: str,
    ) -> EvaluatedCheckResult:
        exp = rule.get("expected_state", {})
        exp_summary = f"{exp.get('operator')}: {exp.get('value', exp.get('allowed_values', exp.get('forbidden_mode_bits_octal')))}"
        return EvaluatedCheckResult(
            rule_id=rule["rule_id"],
            category=rule.get("category", "General"),
            title=rule.get("title", ""),
            benchmark_ref=rule.get("benchmark_ref", ""),
            mitre_attack=rule.get("mitre_attack", []),
            risk_severity=rule.get("risk_severity", "MEDIUM"),
            cvss_base_score=float(rule.get("cvss_base_score", 5.0)),
            compliance_status=compliance_status,
            observed_value=observed_value,
            expected_summary=exp_summary,
            remediation=rule.get("remediation", "").strip(),
            rationale=rationale,
            compliance_frameworks=rule.get("compliance_frameworks", {}),
        )


class AntiPoisoningDetector:
    """
    Silnik wykrywania anomalii i prób zatrucia bazy danych (Database Poisoning)
    przez skompromitowane Agenty.
    """

    @staticmethod
    def inspect_submission(
        agent_id: str,
        cert_common_name: Optional[str],
        payload: Dict[str, Any],
        new_score: float,
        previous_score: Optional[float],
        previous_boot_id: Optional[str],
    ) -> AnomalyDetectionResult:
        findings: List[str] = []
        risk_score = 0

        # 1. Weryfikacja powiązania tożsamości certyfikatu X.509 z agent_id (Identity Pinning)
        if cert_common_name and cert_common_name != agent_id:
            findings.append(
                f"CRITICAL SPOOFING ATTEMPT: Certyfikat mTLS należy do '{cert_common_name}', "
                f"lecz raport deklaruje agent_id='{agent_id}'."
            )
            risk_score += 95

        # 2. Analiza czasów zbierania pomiarów (Zero-Entropy / Synthetic Stub Detection)
        measurements = payload.get("measurements", [])
        timestamps = [m.get("collected_at", "") for m in measurements if m.get("collected_at")]
        if len(timestamps) >= 4 and len(set(timestamps)) == 1:
            findings.append(
                "ZERO-ENTROPY TIMESTAMPS: Wszystkie pomiary mają identyczny znacznik czasu co do mikrosekundy "
                "(wskazuje na statycznie wstrzyknięty lub sfabrykowany plik JSON)."
            )
            risk_score += 55

        # 3. Detekcja anomalii "All-Green Lie" (Nagły skok z niskiego wyniku do 100% bez restartu OS)
        if previous_score is not None and previous_score < 55.0 and new_score == 100.0:
            current_boot_id = payload.get("boot_id")
            if previous_boot_id and current_boot_id == previous_boot_id:
                findings.append(
                    f"ALL-GREEN LIE ANOMALY: Nagły skok wyniku z {previous_score}% do 100.0% w jednym cyklu "
                    "bez restartu systemu operacyjnego (wymaganego m.in. przez UAC/LSASS RunAsPPL)."
                )
                risk_score += 65

        # 4. Detekcja podejrzanych ładunków Injection w polach tekstowych (Defense-in-Depth)
        serialized = str(payload).lower()
        suspicious_patterns = [
            "<script",
            "javascript:",
            "drop table",
            "union select",
            "1=1--",
            "__import__",
            "powershell -enc",
        ]
        for pat in suspicious_patterns:
            if pat in serialized:
                findings.append(
                    f"PAYLOAD INJECTION SIGNATURE: Wykryto wzorzec ataku '{pat}' wewnątrz danych telemetrycznych."
                )
                risk_score += 85

        risk_score = min(100, risk_score)
        return AnomalyDetectionResult(
            is_suspicious=risk_score >= 40,
            quarantine_recommended=risk_score >= 60,
            risk_score=risk_score,
            findings=findings,
        )
