#!/usr/bin/env python3
"""
SystemAuditor Enterprise — Skrypt Autodiagnostyczny (Zero-Dependency)
====================================================================
Uruchom na serwerze lub hoście końcowym:
    python3 diagnose.py
"""

import os
import platform
import socket
import sys
import urllib.request
import urllib.error
import json
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

def main():
    print("=" * 72)
    print("   SystemAuditor Enterprise — Narzędzie Szybkiej Diagnostyki   ")
    print("=" * 72)

    base_dir = Path(__file__).resolve().parent
    is_linux = platform.system().lower() == "linux"
    is_windows = platform.system().lower() == "windows"

    # 1. Sprawdzenie wersji Pythona
    py_ver = sys.version_info
    print(f"\n[1] Interpreter Python:")
    print(f"    Wersja: {py_ver.major}.{py_ver.minor}.{py_ver.micro} ({platform.architecture()[0]})")
    if py_ver < (3, 8):
        print("    ❌ BŁĄD: Wymagany Python 3.8 lub nowszy!")
    else:
        print("    ✅ Wersja Pythona poprawna (>= 3.8)")

    # 2. Sprawdzenie uprawnień
    is_root_or_admin = False
    if is_windows:
        try:
            import ctypes
            is_root_or_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            pass
    else:
        try:
            is_root_or_admin = (os.geteuid() == 0)
        except Exception:
            pass

    print(f"\n[2] Poziom uprawnień procesu:")
    if is_root_or_admin:
        print("    ✅ Uprawnienia podwyższone (root / Administrator)")
    else:
        print("    ⚠️ OSTRZEŻENIE: Uruchomiono jako zwykły użytkownik bez uprawnień root/Administrator.")
        if is_linux:
            print("       -> Niektóre kontrole (np. /etc/sudoers) zakończą się błędem [Errno 13] Permission denied.")
            print("       -> Rozwiązanie: Użyj 'sudo python3 ...'")
        elif is_windows:
            print("       -> Odczyt BitLocker czy niektórych kluczy SAM może wymagać trybu Administratora.")
            print("       -> Rozwiązanie: Uruchom terminal PowerShell jako Administrator.")

    # 3. Sprawdzenie zależności serwera (jeśli obecny jest katalog backend/)
    has_backend = (base_dir / "backend" / "main.py").exists()
    if has_backend:
        print(f"\n[3] Weryfikacja zależności Serwera Centralnego (FastAPI/Backend):")
        packages = ["fastapi", "uvicorn", "pydantic", "yaml"]
        missing = []
        for pkg in packages:
            try:
                __import__(pkg)
                print(f"    ✅ Pakiet '{pkg}': zainstalowany")
            except ImportError:
                print(f"    ❌ Pakiet '{pkg}': BRAK")
                missing.append(pkg)
        if missing:
            print(f"\n    💡 Aby zainstalować brakujące pakiety, wykonaj:")
            print(f"       pip install -r requirements.txt")

        # Katalog reguł
        cat_file = base_dir / "rules_catalog.yaml"
        if cat_file.exists():
            print(f"    ✅ Plik reguł 'rules_catalog.yaml': istnieje ({cat_file.stat().st_size} bajtów)")
        else:
            print(f"    ❌ Plik 'rules_catalog.yaml': NIE ZNALEZIONO w {base_dir}")

    # 4. Sprawdzenie Agenta (agent_poc.py)
    agent_file = base_dir / "agent_poc.py"
    if agent_file.exists():
        print(f"\n[4] Autodiagnostyka kolektorów Agenta (agent_poc.py):")
        try:
            sys.path.insert(0, str(base_dir))
            from agent_poc import OSParameterCollector
            c = OSParameterCollector()
            measurements = c.collect_security_parameters(full_suite=True)
            ok_cnt = sum(1 for m in measurements if m.status == "COLLECTED")
            err_cnt = sum(1 for m in measurements if m.status == "ERROR")
            na_cnt = sum(1 for m in measurements if m.status == "NOT_APPLICABLE")
            print(f"    ✅ Wykonano {len(measurements)} kontroli natywnych OS:")
            print(f"       - Poprawnie pobrane: {ok_cnt}")
            print(f"       - Nie dotyczy (N/A): {na_cnt}")
            print(f"       - Błędy odczytu:     {err_cnt}")

            if err_cnt > 0:
                print(f"    ⚠️ Lista kontroli z błędami odczytu:")
                for m in measurements:
                    if m.status == "ERROR":
                        print(f"       * {m.check_id}: {m.error_message}")
        except Exception as exc:
            print(f"    ❌ Błąd podczas testu kolektorów: {exc}")

    # 5. Sprawdzenie łączności z portem 8000
    print(f"\n[5] Test łączności z Serwerem Centralnym:")
    test_urls = ["http://127.0.0.1:8000/health", "http://localhost:8000/health"]
    connected = False
    for u in test_urls:
        try:
            req = urllib.request.Request(u, headers={"User-Agent": "SystemAuditor-Diagnose"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    print(f"    ✅ Połączono z {u} (Status: {data.get('status')}, Reguły: {data.get('rules_catalog', {}).get('total_rules')})")
                    connected = True
                    break
        except Exception:
            pass

    if not connected:
        print("    ℹ️ Brak działającego backendu na localhost:8000.")
        print("       Jeśli uruchamiasz serwer, wykonaj:")
        print("       python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000")
        print("       Jeśli agent łączy się ze zdalnym serwerem, użyj flagi:")
        print("       python agent_poc.py --server http://<IP_SERWERA>:8000 --diagnose")

    print("\n" + "=" * 72)
    print(" Diagnostyka zakończona.")
    print("=" * 72)

if __name__ == "__main__":
    main()
