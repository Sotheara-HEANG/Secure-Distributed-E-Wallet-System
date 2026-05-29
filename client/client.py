"""
client.py — Secure E-Wallet RPC Client
=========================================
An interactive command-line client that:
  1. Connects to the Auth Service to register/login
  2. Receives an encrypted session key + server ticket
  3. Handshakes with the App Server using the ticket
  4. Performs secure RPC calls (deposit, withdraw, transfer, check balance)

All RPC communications are encrypted using AES-256-GCM with the session key.
Includes a debug mode to show raw encrypted bytes on the wire.
"""

import os
import sys
import json
import socket
import base64

# Add the project root to the Python path so we can import 'common'
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from common import crypto
from common import rpc_protocol


# =============================================================================
#  Configuration
# =============================================================================

AUTH_HOST = "127.0.0.1"
AUTH_PORT = 8001
APP_HOST = "127.0.0.1"
APP_PORT = 8002

# Key file paths
PROJECT_ROOT = os.path.join(os.path.dirname(__file__), "..")
KEYS_DIR = os.path.join(PROJECT_ROOT, "keys")
CLIENT_PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "client_private.pem")
CLIENT_PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "client_public.pem")


# =============================================================================
#  Client State
# =============================================================================

class ClientState:
    """Holds the current client session state."""
    def __init__(self):
        self.username = None
        self.session_key = None          # AES-256 session key (bytes)
        self.encrypted_ticket = None     # Encrypted ticket for App Server (str)
        self.app_socket = None           # Persistent TCP connection to App Server
        self.is_authenticated = False
        self.is_connected = False
        self.debug_mode = False          # Show raw encrypted bytes
        self.private_key = None          # Client's RSA private key
        self.public_key = None           # Client's RSA public key


state = ClientState()


# =============================================================================
#  Key Management
# =============================================================================

def generate_client_keys():
    """Generate or load the client's RSA key pair."""
    if not os.path.exists(CLIENT_PRIVATE_KEY_PATH) or not os.path.exists(CLIENT_PUBLIC_KEY_PATH):
        print("[Client] Generating RSA key pair...")
        private_key, public_key = crypto.generate_rsa_keypair()
        crypto.save_private_key(private_key, CLIENT_PRIVATE_KEY_PATH)
        crypto.save_public_key(public_key, CLIENT_PUBLIC_KEY_PATH)
        print(f"[Client] Keys saved to {KEYS_DIR}")
    else:
        print("[Client] Loading existing RSA keys...")
        private_key = crypto.load_private_key(CLIENT_PRIVATE_KEY_PATH)
        public_key = crypto.load_public_key(CLIENT_PUBLIC_KEY_PATH)

    state.private_key = private_key
    state.public_key = public_key
    print("[Client] RSA keys ready")


# =============================================================================
#  Auth Service Communication
# =============================================================================

def _connect_to_auth():
    """Create a TCP connection to the Auth Service."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((AUTH_HOST, AUTH_PORT))
    return sock


def register_user():
    """Register a new user account with the Auth Service."""
    print("\n--- Register New Account ---")
    username = input("  Username: ").strip()
    password = input("  Password: ").strip()

    if not username or not password:
        print("  [ERROR] Username and password cannot be empty!")
        return

    try:
        sock = _connect_to_auth()
        request = rpc_protocol.build_request("register", username=username, password=password)
        rpc_protocol.send_message(sock, request)

        response = rpc_protocol.recv_message(sock)
        sock.close()

        if response and response.get("status") == "success":
            print(f"  [OK] {response['data']['message']}")
        else:
            print(f"  [ERROR] {response.get('message', 'Registration failed')}")
    except ConnectionRefusedError:
        print("  [ERROR] Cannot connect to Auth Service! Is it running?")
    except Exception as e:
        print(f"  [ERROR] {e}")


def login_user():
    """
    Login to the Auth Service and receive session key + server ticket.
    
    Steps:
      1. Send credentials + client public key to Auth Service
      2. Receive encrypted session key (encrypted with our public key)
      3. Receive encrypted ticket (encrypted with App Server's public key)
      4. Decrypt the session key using our private key
    """
    print("\n--- Login ---")
    username = input("  Username: ").strip()
    password = input("  Password: ").strip()

    if not username or not password:
        print("  [ERROR] Username and password cannot be empty!")
        return

    try:
        sock = _connect_to_auth()

        # Send login request with our public key
        client_pub_pem = crypto.serialize_public_key(state.public_key)
        request = rpc_protocol.build_request(
            "login",
            username=username,
            password=password,
            client_public_key=client_pub_pem,
        )
        rpc_protocol.send_message(sock, request)
        print("  [Client] Sent login request to Auth Service")

        # Receive response
        response = rpc_protocol.recv_message(sock)
        sock.close()

        if response is None or response.get("status") != "success":
            print(f"  [ERROR] {response.get('message', 'Login failed')}")
            return

        data = response["data"]
        encrypted_session_key = data["encrypted_session_key"]
        encrypted_ticket = data["encrypted_ticket"]

        print(f"  [Client] Received encrypted session key from Auth Service")
        print(f"  [Client] Received encrypted ticket for App Server")

        if state.debug_mode:
            print(f"\n  [DEBUG] Encrypted Session Key (base64): {encrypted_session_key[:80]}...")
            print(f"  [DEBUG] Encrypted Ticket (base64): {encrypted_ticket[:80]}...")

        # Decrypt the session key using our RSA private key
        print(f"  [Client] Decrypting session key with Client's RSA private key...")
        session_key = crypto.rsa_decrypt(state.private_key, encrypted_session_key)

        state.username = username
        state.session_key = session_key
        state.encrypted_ticket = encrypted_ticket
        state.is_authenticated = True

        print(f"  [OK] Login successful! Welcome, {username}!")
        print(f"  [Client] AES-256 session key obtained ({len(session_key)} bytes)")

        if state.debug_mode:
            print(f"  [DEBUG] Session Key (hex): {session_key.hex()}")

    except ConnectionRefusedError:
        print("  [ERROR] Cannot connect to Auth Service! Is it running?")
    except Exception as e:
        print(f"  [ERROR] {e}")


# =============================================================================
#  App Server Communication
# =============================================================================

def connect_to_app_server():
    """
    Perform the handshake with the App Server using the encrypted ticket.
    
    Steps:
      1. Connect to the App Server via TCP
      2. Send the encrypted ticket (handshake)
      3. Receive an AES-encrypted ACK from the server
      4. Decrypt the ACK to confirm the session is established
    """
    if not state.is_authenticated:
        print("  [ERROR] You must login first!")
        return

    print(f"\n  [Client] Connecting to App Server at {APP_HOST}:{APP_PORT}...")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((APP_HOST, APP_PORT))

        # Send the handshake with the encrypted ticket
        handshake = rpc_protocol.build_request("handshake", encrypted_ticket=state.encrypted_ticket)
        rpc_protocol.send_message(sock, handshake)
        print("  [Client] Sent encrypted ticket to App Server")

        if state.debug_mode:
            print(f"  [DEBUG] Ticket sent (base64): {state.encrypted_ticket[:80]}...")

        # Receive the encrypted ACK
        ack_message = rpc_protocol.recv_message(sock)
        if ack_message is None:
            print("  [ERROR] No response from App Server")
            sock.close()
            return

        if "encrypted_payload" not in ack_message:
            # Server sent an unencrypted error (e.g., invalid ticket)
            print(f"  [ERROR] {ack_message.get('message', 'Handshake failed')}")
            sock.close()
            return

        # Decrypt the ACK using our session key
        encrypted_ack = ack_message["encrypted_payload"]
        ack_bytes = crypto.aes_decrypt(state.session_key, encrypted_ack)
        ack_data = json.loads(ack_bytes.decode("utf-8"))

        print(f"  [OK] {ack_data['message']}")
        print(f"  [Client] Secure session established with App Server!")

        state.app_socket = sock
        state.is_connected = True

    except ConnectionRefusedError:
        print("  [ERROR] Cannot connect to App Server! Is it running?")
    except Exception as e:
        print(f"  [ERROR] Handshake failed: {e}")


def send_rpc_request(action, **kwargs):
    """
    Send an encrypted RPC request to the App Server and return the decrypted response.
    
    Args:
        action: RPC method name (e.g., "deposit", "withdraw")
        **kwargs: Method arguments
    
    Returns:
        dict: Decrypted response data, or None on error
    """
    if not state.is_connected:
        print("  [ERROR] Not connected to App Server! Connect first.")
        return None

    try:
        # Build the RPC request
        request_data = rpc_protocol.build_request(action, **kwargs)
        request_bytes = json.dumps(request_data).encode("utf-8")

        if state.debug_mode:
            print(f"\n  [DEBUG] Plaintext request: {request_bytes.decode()}")

        # Encrypt the request with AES-GCM
        encrypted_request = crypto.aes_encrypt(state.session_key, request_bytes)

        if state.debug_mode:
            print(f"  [DEBUG] Encrypted request (base64): {encrypted_request[:80]}...")

        # Send the encrypted request
        rpc_protocol.send_message(state.app_socket, {"encrypted_payload": encrypted_request})

        # Receive the encrypted response
        response_message = rpc_protocol.recv_message(state.app_socket)
        if response_message is None:
            print("  [ERROR] Lost connection to App Server")
            state.is_connected = False
            return None

        encrypted_response = response_message.get("encrypted_payload", "")

        if state.debug_mode:
            print(f"  [DEBUG] Encrypted response (base64): {encrypted_response[:80]}...")

        # Decrypt the response
        response_bytes = crypto.aes_decrypt(state.session_key, encrypted_response)
        response_data = json.loads(response_bytes.decode("utf-8"))

        if state.debug_mode:
            print(f"  [DEBUG] Decrypted response: {response_bytes.decode()}")

        return response_data

    except Exception as e:
        print(f"  [ERROR] RPC call failed: {e}")
        state.is_connected = False
        return None


# =============================================================================
#  Interactive CLI Menu Actions
# =============================================================================

def check_balance():
    """Check the user's current balance."""
    print("\n--- Check Balance ---")
    response = send_rpc_request("get_balance")
    if response and response.get("status") == "success":
        balance = response["data"]["balance"]
        print(f"  [OK] Your current balance: ${balance:.2f}")
    elif response:
        print(f"  [ERROR] {response.get('message', 'Failed to get balance')}")


def deposit():
    """Deposit money into the account."""
    print("\n--- Deposit ---")
    try:
        amount = float(input("  Amount to deposit: $"))
    except ValueError:
        print("  [ERROR] Invalid amount!")
        return

    response = send_rpc_request("deposit", amount=amount)
    if response and response.get("status") == "success":
        data = response["data"]
        print(f"  [OK] {data['message']}")
        print(f"  [OK] New balance: ${data['balance']:.2f}")
    elif response:
        print(f"  [ERROR] {response.get('message', 'Deposit failed')}")


def withdraw():
    """Withdraw money from the account."""
    print("\n--- Withdraw ---")
    try:
        amount = float(input("  Amount to withdraw: $"))
    except ValueError:
        print("  [ERROR] Invalid amount!")
        return

    response = send_rpc_request("withdraw", amount=amount)
    if response and response.get("status") == "success":
        data = response["data"]
        print(f"  [OK] {data['message']}")
        print(f"  [OK] New balance: ${data['balance']:.2f}")
    elif response:
        print(f"  [ERROR] {response.get('message', 'Withdrawal failed')}")


def transfer():
    """Transfer money to another user."""
    print("\n--- Transfer ---")
    to_user = input("  Recipient username: ").strip()
    try:
        amount = float(input("  Amount to transfer: $"))
    except ValueError:
        print("  [ERROR] Invalid amount!")
        return

    response = send_rpc_request("transfer", to_user=to_user, amount=amount)
    if response and response.get("status") == "success":
        data = response["data"]
        print(f"  [OK] {data['message']}")
        print(f"  [OK] Your new balance: ${data['balance']:.2f}")
    elif response:
        print(f"  [ERROR] {response.get('message', 'Transfer failed')}")


def toggle_debug():
    """Toggle debug mode to show/hide encrypted data on the wire."""
    state.debug_mode = not state.debug_mode
    status = "ON" if state.debug_mode else "OFF"
    print(f"\n  [Client] Debug mode: {status}")
    if state.debug_mode:
        print("  [Client] You will now see the raw encrypted bytes for each RPC call.")
        print("  [Client] This proves that data on the wire is unreadable ciphertext.")


def disconnect():
    """Disconnect from the App Server."""
    if state.app_socket:
        try:
            # Notify server
            request_data = rpc_protocol.build_request("disconnect")
            request_bytes = json.dumps(request_data).encode("utf-8")
            encrypted = crypto.aes_encrypt(state.session_key, request_bytes)
            rpc_protocol.send_message(state.app_socket, {"encrypted_payload": encrypted})
        except Exception:
            pass
        try:
            state.app_socket.close()
        except Exception:
            pass
    state.app_socket = None
    state.is_connected = False
    state.is_authenticated = False
    state.session_key = None
    state.encrypted_ticket = None
    state.username = None
    print("  [Client] Disconnected. Session cleared.")


# =============================================================================
#  Interactive CLI Menu
# =============================================================================

def print_menu():
    """Display the interactive menu with perfect box alignment."""
    width = 50  # Width of content inside borders
    print()
    print("╔" + "═" * width + "╗")
    print("║" + "SECURE E-WALLET SYSTEM".center(width) + "║")
    print("╠" + "═" * width + "╣")

    # Status bar
    if state.is_connected:
        status_text = f"  User: {state.username} | Status: CONNECTED"
    elif state.is_authenticated:
        status_text = f"  User: {state.username} | Status: LOGGED IN"
    else:
        status_text = "  User: (none) | Status: OFFLINE"

    print("║" + status_text.ljust(width) + "║")
    print("╠" + "═" * width + "╣")
    
    debug_status = "ON" if state.debug_mode else "OFF"
    menu_items = [
        "  1. Register New Account",
        "  2. Login",
        "  3. Connect to App Server (Handshake)",
        "  4. Check Balance",
        "  5. Deposit",
        "  6. Withdraw",
        "  7. Transfer",
        f"  8. Toggle Encryption Debug Mode [{debug_status}]",
        "  9. Disconnect & Logout",
        "  0. Exit"
    ]

    for item in menu_items:
        print("║" + item.ljust(width) + "║")
    print("╚" + "═" * width + "╝")


def run_interactive_client():
    """Main interactive loop for the E-Wallet client."""
    print("=" * 60)
    print("  SECURE E-WALLET CLIENT")
    print("  RPC over TCP with RSA + AES-GCM Encryption")
    print("=" * 60)

    generate_client_keys()

    while True:
        print_menu()
        choice = input("  Select option: ").strip()

        if choice == "1":
            register_user()
        elif choice == "2":
            login_user()
        elif choice == "3":
            connect_to_app_server()
        elif choice == "4":
            check_balance()
        elif choice == "5":
            deposit()
        elif choice == "6":
            withdraw()
        elif choice == "7":
            transfer()
        elif choice == "8":
            toggle_debug()
        elif choice == "9":
            disconnect()
        elif choice == "0":
            disconnect()
            print("\n  Goodbye!")
            break
        else:
            print("  [ERROR] Invalid option. Please try again.")


# =============================================================================
#  Main — Run as standalone client
# =============================================================================

if __name__ == "__main__":
    run_interactive_client()
