"""
SystemAuditor Enterprise — Zunifikowany Skrypt Uruchomieniowy (All-in-One Launcher)
===================================================================================
Uruchamia cały ekosystem jednym poleceniem:
1. Sprawdza wymagane pakiety Python oraz automatycznie wybiera wolny port TCP.
2. Opcjonalnie uruchamia zestaw testów bezpieczeństwa End-to-End (`test_e2e.py`).
3. Uruchamia Serwer Centralny FastAPI (Uvicorn) i czeka na gotowość API.
4. Wykonuje natywny audyt bezpieczeństwa CIS na bieżącym systemie (`agent_poc.py`)
   i przesyła podpisany raport HMAC-SHA256 do serwera.
5. Automatycznie otwiera Dashboard Webowy SOC (Security Posture) w przeglądarce.
"""

import argparse
import os
import socket
import subprocess
import sys
import time
import urllib.request
import webbrowser
from pathlib import Path

os.environ["PYTHONUTF8"] = "1"
os.environ["PYTHONIOENCODING"] = "utf-8"

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

BASE_DIR = Path(__file__).resolve().parent


def print_banner() -> None:
    print("=" * 78)
    print("   ____            _                 _             _ _ _             ")
    print("  / ___| _   _ ___| |_ ___ _ __ ___ / \\  _   _  __| (_) |_ ___  _ __ ")
    print("  \\___ \\| | | / __| __/ _ \\ '_ ` _ \\/ _ \\| | | |/ _` | | __/ _ \\| '__|")
    print("   ___) | |_| \\__ \\ ||  __/ | | | | / ___ \\ |_| | (_| | | || (_) | |   ")
    print("  |____/ \\__, |___/\\__\\___|_| |_| |_/_/   \\_\\__,_|\\__,_|_|\\__\\___/|_|   ")
    print("         |___/   ENTERPRISE ZERO-TRUST OS COMPLIANCE PLATFORM v2.0      ")
    print("=" * 78)


def verify_dependencies() -> None:
    required = ["fastapi", "uvicorn", "pydantic", "yaml", "cryptography", "requests"]
    missing = []
    for mod in required:
        try:
            __import__(mod)
        except ImportError:
            missing.append("pyyaml" if mod == "yaml" else mod)

    if missing:
        print(f"[*] Instalowanie brakujących pakietów: {', '.join(missing)}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", *missing])


def is_port_free(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) != 0


def find_available_port(host: str, preferred_port: int) -> int:
    if is_port_free(host, preferred_port):
        return preferred_port
    for candidate in range(preferred_port + 1, preferred_port + 50):
        if is_port_free(host, candidate):
            print(f"[!] Port {preferred_port} jest zajęty. Automatycznie wybrano wolny port: {candidate}")
            return candidate
    return preferred_port


def wait_for_server(url: str, timeout_sec: float = 20.0) -> bool:
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1.5) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(0.4)
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="SystemAuditor Enterprise — Launcher Całości")
    parser.add_argument("--host", default="127.0.0.1", help="Adres IP nasłuchiwania serwera (domyślnie: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port TCP serwera (domyślnie: 8000)")
    parser.add_argument("--no-browser", action="store_true", help="Nie otwieraj automatycznie przeglądarki")
    parser.add_argument("--skip-tests", action="store_true", help="Pomiń startowy test weryfikacyjny E2E")
    args = parser.parse_args()

    print_banner()
    verify_dependencies()

    port = find_available_port("127.0.0.1" if args.host == "0.0.0.0" else args.host, args.port)
    connect_host = "127.0.0.1" if args.host == "0.0.0.0" else args.host
    server_url = f"http://{connect_host}:{port}"

    child_env = os.environ.copy()
    child_env["PYTHONUTF8"] = "1"
    child_env["PYTHONIOENCODING"] = "utf-8"

    # 1. Szybka weryfikacja integralności PKI, Ed25519 oraz Anti-Poisoning
    if not args.skip_tests:
        print("\n[1/4] Weryfikacja kryptografii Zero-Trust PKI, podpisów Ed25519 i ochrony Anti-Poisoning...")
        test_res = subprocess.run(
            [sys.executable, str(BASE_DIR / "test_e2e.py")],
            cwd=str(BASE_DIR),
            env=child_env,
        )
        if test_res.returncode != 0:
            print("[!] Ostrzeżenie: Testy wstępne zwróciły kod błędu, kontynuowanie uruchamiania serwera...")

    # 2. Uruchomienie Serwera Centralnego FastAPI
    print(f"\n[2/4] Uruchamianie Serwera Centralnego FastAPI pod adresem {server_url} ...")
    server_proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "backend.main:app",
            "--host",
            args.host,
            "--port",
            str(port),
            "--reload",
        ],
        cwd=str(BASE_DIR),
        env=child_env,
    )

    try:
        if not wait_for_server(f"{server_url}/api/v1/dashboard/overview"):
            print("[!] Serwer nie odpowiedział w wyznaczonym czasie.")
            server_proc.terminate()
            return 1

        print(f"[OK] Serwer Centralny oraz silnik CIS Rule Engine są aktywne ({server_url}).")

        # 3. Uruchomienie natywnego Agenta na żywo na bieżącej maszynie
        print("\n[3/4] Uruchamianie Agenta Endpoint (agent_poc.py) — skanowanie natywnych parametrów tego systemu OS...")
        subprocess.run(
            [sys.executable, str(BASE_DIR / "agent_poc.py"), "--server", server_url],
            cwd=str(BASE_DIR),
            env=child_env,
            check=False,
        )

        # 4. Otwarcie Dashboardu GUI w przeglądarce
        if not args.no_browser:
            print(f"\n[4/4] Otwieranie panelu Security Posture Dashboard w przeglądarce: {server_url}")
            webbrowser.open(server_url)

        print("\n" + "=" * 78)
        print(f" SYSTEM DZIAŁA! Otwórz w przeglądarce: {server_url}")
        print(f" Dokumentacja REST API (Swagger):      {server_url}/docs")
        print(" Naciśnij Ctrl+C w tym oknie, aby zatrzymać serwer.")
        print("=" * 78 + "\n")

        server_proc.wait()
        return 0

    except KeyboardInterrupt:
        print("\n[*] Otrzymano sygnał zatrzymania (Ctrl+C). Zamykanie Serwera Centralnego...")
        server_proc.terminate()
        try:
            server_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server_proc.kill()
        print("[OK] SystemAuditor został bezpiecznie zatrzymany.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
