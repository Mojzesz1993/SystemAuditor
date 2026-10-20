#!/usr/bin/env python3
"""
SystemAuditor Enterprise — Skrypt Startowy Serwera Centralnego
============================================================
Użycie:
    python run_server.py
    (lub: python3 run_server.py --port 8000 --host 0.0.0.0)
"""

import argparse
import os
import platform
import socket
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

def check_dependencies():
    required = {
        "fastapi": "fastapi>=0.110.0",
        "uvicorn": "uvicorn>=0.28.0",
        "pydantic": "pydantic>=2.0.0",
        "yaml": "pyyaml>=6.0.0",
        "cryptography": "cryptography>=42.0.0",
    }
    missing = []
    for mod, pkg in required.items():
        try:
            __import__(mod)
        except ImportError:
            missing.append(pkg)

    if missing:
        print("=" * 72)
        print(" ❌ BŁĄD: Brak wymaganych bibliotek Pythona do uruchomienia serwera!")
        print("=" * 72)
        print(" Brakujące pakiety:")
        for m in missing:
            print(f"   • {m}")
        print("\n 💡 Rozwiązanie: Zainstaluj brakujące zależności poleceniem:")
        print(f"   {sys.executable} -m pip install -r requirements.txt")
        print("=" * 72)
        sys.exit(1)

def get_lan_ips():
    ips = []
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127.") and ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    if not ips:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                ips.append(s.getsockname()[0])
        except Exception:
            pass
    return ips

def check_port_available(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        res = s.connect_ex(("127.0.0.1" if host == "0.0.0.0" else host, port))
        return res != 0

def main():
    parser = argparse.ArgumentParser(description="SystemAuditor Enterprise Central Server Launcher")
    parser.add_argument("--host", default=os.environ.get("AUDITOR_HOST", "0.0.0.0"), help="Adres nasłuchu (domyślnie 0.0.0.0)")
    parser.add_argument("--port", type=int, default=int(os.environ.get("AUDITOR_PORT", "8000")), help="Port serwera (domyślnie 8000)")
    parser.add_argument("--reload", action="store_true", help="Tryb automatycznego przeładowywania kodu (Dev)")
    args = parser.parse_args()

    # 1. Sprawdzenie zależności pip
    check_dependencies()

    # 2. Sprawdzenie zajętości portu
    if not check_port_available(args.host, args.port):
        print("=" * 72)
        print(f" ⚠️ UWAGA: Port {args.port} jest już zajęty przez inny proces!")
        print("=" * 72)
        if platform.system().lower() == "windows":
            print(f" Aby sprawdzić i zamknąć proces blokujący port {args.port}, wykonaj w PowerShell:")
            print(f"   Get-NetTCPConnection -LocalPort {args.port} | ForEach-Object {{ Stop-Process -Id $_.OwningProcess -Force }}")
        else:
            print(f" Aby sprawdzić i zamknąć proces blokujący port {args.port}, wykonaj w terminalu:")
            print(f"   sudo fuser -k {args.port}/tcp   (lub: sudo lsof -ti:{args.port} | xargs sudo kill -9)")
        print(f"\n Możesz również uruchomić SystemAuditor na innym wolnym porcie, np.:")
        print(f"   python run_server.py --port 8080")
        print("=" * 72)
        sys.exit(1)

    # 3. Informacje powitalne
    lan_ips = get_lan_ips()
    print("=" * 72)
    print("    SystemAuditor Enterprise — Zero-Trust OS Security Platform    ")
    print("=" * 72)
    print(f" • Stan serwera:     INICJALIZACJA...")
    print(f" • Interfejsy:       http://{args.host}:{args.port}")
    print(f" • Dashboard GUI:    http://localhost:{args.port}")
    print(f" • Healthcheck API:  http://localhost:{args.port}/health")
    if lan_ips:
        print(f" • Adres w sieci LAN: http://{lan_ips[0]}:{args.port}")
        print(f"   (Podaj ten adres w agentach: python agent_poc.py --server http://{lan_ips[0]}:{args.port})")
    print("=" * 72)

    root_dir = Path(__file__).resolve().parent
    if str(root_dir) not in sys.path:
        sys.path.insert(0, str(root_dir))

    import uvicorn
    uvicorn.run("backend.main:app", host=args.host, port=args.port, reload=args.reload)

if __name__ == "__main__":
    main()
