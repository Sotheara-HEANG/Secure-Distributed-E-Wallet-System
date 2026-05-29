"""
run_demo.py — Master Launcher for the Secure E-Wallet System
===============================================================
This script:
  1. Generates all RSA keys (Auth, Server, Client) if they don't exist
  2. Starts the Authentication Service in a background thread
  3. Starts the App Server in a background thread
  4. Launches the interactive Client in the foreground

Usage:
  python run_demo.py
"""

import os
import sys
import time

# Ensure the project root is in the Python path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

from common import crypto

# Key file paths
KEYS_DIR = os.path.join(PROJECT_ROOT, "keys")
KEY_PAIRS = {
    "Auth Service": ("auth_private.pem", "auth_public.pem"),
    "App Server": ("server_private.pem", "server_public.pem"),
    "Client": ("client_private.pem", "client_public.pem"),
}


def generate_all_keys():
    """Generate RSA key pairs for all components if they don't exist."""
    print("=" * 60)
    print("  KEY GENERATION")
    print("=" * 60)

    os.makedirs(KEYS_DIR, exist_ok=True)

    for name, (priv_file, pub_file) in KEY_PAIRS.items():
        priv_path = os.path.join(KEYS_DIR, priv_file)
        pub_path = os.path.join(KEYS_DIR, pub_file)

        if os.path.exists(priv_path) and os.path.exists(pub_path):
            print(f"  [OK] {name} keys already exist")
        else:
            print(f"  [GENERATING] {name} RSA-2048 key pair...")
            private_key, public_key = crypto.generate_rsa_keypair()
            crypto.save_private_key(private_key, priv_path)
            crypto.save_public_key(public_key, pub_path)
            print(f"  [OK] {name} keys saved to {KEYS_DIR}")

    print()


def main():
    """Main entry point — start all services and the client."""
    print()
    print("╔" + "═" * 58 + "╗")
    print("║                                                          ║")
    print("║          SECURE DISTRIBUTED E-WALLET SYSTEM              ║")
    print("║    RPC over TCP  |  RSA + AES-GCM Encryption             ║")
    print("║    Multi-Threaded  |  Authentication Service             ║")
    print("║                                                          ║")
    print("╚" + "═" * 58 + "╝")
    print()

    # Step 1: Generate all RSA keys
    generate_all_keys()

    # Step 2: Start the Auth Service in a background thread
    print("=" * 60)
    print("  STARTING AUTHENTICATION SERVICE")
    print("=" * 60)
    from auth_service.auth_server import start_auth_server
    auth_server = start_auth_server(blocking=False)
    time.sleep(0.5)  # Give the server time to bind the port

    # Step 3: Start the App Server in a background thread
    print("=" * 60)
    print("  STARTING APP SERVER")
    print("=" * 60)
    from app_server.server import start_app_server
    app_server = start_app_server(blocking=False)
    time.sleep(0.5)  # Give the server time to bind the port

    # Step 4: Launch the interactive Client
    print()
    print("=" * 60)
    print("  ALL SERVICES RUNNING — LAUNCHING CLIENT")
    print("=" * 60)
    print()
    print("  Tip: Start by registering a new account (Option 1),")
    print("  then login (Option 2), then connect (Option 3).")
    print("  Toggle debug mode (Option 8) to see encrypted data!")
    print()

    from client.client import run_interactive_client

    try:
        run_interactive_client()
    except KeyboardInterrupt:
        print("\n\n  [System] Shutting down...")

    # Shutdown servers
    print("\n  [System] Stopping servers...")
    auth_server.shutdown()
    app_server.shutdown()
    print("  [System] All services stopped. Goodbye!")


if __name__ == "__main__":
    main()
