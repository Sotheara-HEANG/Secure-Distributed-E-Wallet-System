"""
server.py — Application Server (E-Wallet RPC Server)
======================================================
A multi-threaded TCP server that provides secure E-Wallet banking operations.

Supported RPC methods (all encrypted with AES-GCM):
  - get_balance:  Returns the authenticated user's current balance
  - deposit:      Adds money to the user's account (thread-safe)
  - withdraw:     Subtracts money if sufficient funds exist (thread-safe)
  - transfer:     Moves money between users (thread-safe, locks both accounts)

Security Flow:
  1. Client sends an encrypted Ticket (issued by the Auth Service)
  2. Server decrypts the Ticket using its RSA private key
  3. Extracts the session key and username from the Ticket
  4. All subsequent RPC requests/responses are encrypted with AES-256-GCM

Parallelism:
  - Uses ThreadingTCPServer — each client gets its own thread
  - Balance operations are protected by threading.Lock() to prevent race conditions
  - Demonstrates parallel & distributed systems concepts (concurrent access, mutual exclusion)

Runs on port 8002 by default.
"""

import os
import sys
import json
import socket
import threading
import socketserver
import base64

# Add the project root to the Python path so we can import 'common'
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from common import crypto
from common import rpc_protocol


# =============================================================================
#  Configuration
# =============================================================================

APP_HOST = "127.0.0.1"
APP_PORT = 8002

# Key file paths (relative to project root)
PROJECT_ROOT = os.path.join(os.path.dirname(__file__), "..")
KEYS_DIR = os.path.join(PROJECT_ROOT, "keys")
SERVER_PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "server_private.pem")
SERVER_PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "server_public.pem")

# Default starting balance for new users
DEFAULT_BALANCE = 1000.0


# =============================================================================
#  In-Memory E-Wallet Database (thread-safe)
# =============================================================================

wallet_db = {}          # { username: float(balance) }
wallet_db_lock = threading.Lock()


def ensure_account(username):
    """Create an account with default balance if it doesn't exist."""
    with wallet_db_lock:
        if username not in wallet_db:
            wallet_db[username] = DEFAULT_BALANCE
            print(f"[App Server] Created wallet for '{username}' with balance ${DEFAULT_BALANCE:.2f}")


# =============================================================================
#  RPC Method Implementations (Thread-Safe Banking Operations)
# =============================================================================

def rpc_get_balance(username, args):
    """Get the current balance of the authenticated user."""
    with wallet_db_lock:
        balance = wallet_db.get(username, 0.0)
    return rpc_protocol.build_response(
        status="success",
        data={"balance": balance, "username": username}
    )


def rpc_deposit(username, args):
    """Deposit money into the user's account."""
    amount = args.get("amount", 0.0)

    if not isinstance(amount, (int, float)) or amount <= 0:
        return rpc_protocol.build_response(
            status="error",
            message="Deposit amount must be a positive number"
        )

    with wallet_db_lock:
        wallet_db[username] = wallet_db.get(username, 0.0) + amount
        new_balance = wallet_db[username]

    print(f"[App Server] {username} deposited ${amount:.2f} — new balance: ${new_balance:.2f}")
    return rpc_protocol.build_response(
        status="success",
        data={
            "message": f"Deposited ${amount:.2f} successfully",
            "balance": new_balance,
            "username": username,
        }
    )


def rpc_withdraw(username, args):
    """Withdraw money from the user's account (if sufficient funds)."""
    amount = args.get("amount", 0.0)

    if not isinstance(amount, (int, float)) or amount <= 0:
        return rpc_protocol.build_response(
            status="error",
            message="Withdrawal amount must be a positive number"
        )

    with wallet_db_lock:
        current = wallet_db.get(username, 0.0)
        if amount > current:
            return rpc_protocol.build_response(
                status="error",
                message=f"Insufficient funds. Current balance: ${current:.2f}, requested: ${amount:.2f}"
            )
        wallet_db[username] = current - amount
        new_balance = wallet_db[username]

    print(f"[App Server] {username} withdrew ${amount:.2f} — new balance: ${new_balance:.2f}")
    return rpc_protocol.build_response(
        status="success",
        data={
            "message": f"Withdrew ${amount:.2f} successfully",
            "balance": new_balance,
            "username": username,
        }
    )


def rpc_transfer(username, args):
    """
    Transfer money from the authenticated user to another user.
    
    Thread Safety: Acquires the wallet lock to prevent race conditions
    when modifying two accounts simultaneously.
    """
    to_user = args.get("to_user", "").strip()
    amount = args.get("amount", 0.0)

    if not to_user:
        return rpc_protocol.build_response(
            status="error",
            message="Recipient username is required"
        )

    if not isinstance(amount, (int, float)) or amount <= 0:
        return rpc_protocol.build_response(
            status="error",
            message="Transfer amount must be a positive number"
        )

    if to_user == username:
        return rpc_protocol.build_response(
            status="error",
            message="Cannot transfer to yourself"
        )

    with wallet_db_lock:
        # Check sender's balance
        sender_balance = wallet_db.get(username, 0.0)
        if amount > sender_balance:
            return rpc_protocol.build_response(
                status="error",
                message=f"Insufficient funds. Your balance: ${sender_balance:.2f}, requested: ${amount:.2f}"
            )

        # Check if recipient exists
        if to_user not in wallet_db:
            return rpc_protocol.build_response(
                status="error",
                message=f"Recipient '{to_user}' does not have a wallet"
            )

        # Perform the transfer atomically (both operations inside the same lock)
        wallet_db[username] -= amount
        wallet_db[to_user] += amount
        new_sender_balance = wallet_db[username]
        new_recipient_balance = wallet_db[to_user]

    print(f"[App Server] {username} transferred ${amount:.2f} to {to_user}")
    print(f"[App Server]   {username}: ${new_sender_balance:.2f} | {to_user}: ${new_recipient_balance:.2f}")

    return rpc_protocol.build_response(
        status="success",
        data={
            "message": f"Transferred ${amount:.2f} to '{to_user}' successfully",
            "balance": new_sender_balance,
            "username": username,
        }
    )


# =============================================================================
#  RPC Method Registry — maps action names to handler functions
# =============================================================================

RPC_METHODS = {
    "get_balance": rpc_get_balance,
    "deposit": rpc_deposit,
    "withdraw": rpc_withdraw,
    "transfer": rpc_transfer,
}


# =============================================================================
#  App Server Request Handler
# =============================================================================

class AppRequestHandler(socketserver.BaseRequestHandler):
    """
    Handles a single client connection to the App Server.
    
    Connection lifecycle:
      1. Receive the encrypted Ticket (handshake)
      2. Decrypt the Ticket to obtain session key + username
      3. Enter the RPC loop: receive encrypted requests, execute, return encrypted responses
    """

    def handle(self):
        """Process a client connection: handshake, then RPC loop."""
        client_addr = self.client_address
        print(f"\n[App Server] New connection from {client_addr}")

        try:
            # ---- Phase 1: Handshake — Decrypt the Ticket ----
            session_key, username = self._perform_handshake()
            if session_key is None:
                return

            # Ensure the user has a wallet account
            ensure_account(username)

            # ---- Phase 2: Secure RPC Loop ----
            self._rpc_loop(session_key, username)

        except ConnectionResetError:
            print(f"[App Server] Connection reset by {client_addr}")
        except Exception as e:
            print(f"[App Server] Error handling {client_addr}: {e}")

        print(f"[App Server] Connection from {client_addr} closed")

    def _perform_handshake(self):
        """
        Decrypt the client's Ticket to establish a secure session.
        
        Returns:
            tuple: (session_key_bytes, username) or (None, None) on failure
        """
        print(f"[App Server] Waiting for handshake from {self.client_address}...")

        # Receive the handshake message containing the encrypted ticket
        message = rpc_protocol.recv_message(self.request)
        if message is None:
            return None, None

        if message.get("action") != "handshake":
            rpc_protocol.send_message(self.request, rpc_protocol.build_response(
                status="error", message="Expected handshake"
            ))
            return None, None

        encrypted_ticket = message.get("args", {}).get("encrypted_ticket", "")

        # Decrypt the ticket using the App Server's RSA private key
        try:
            server_private_key = crypto.load_private_key(SERVER_PRIVATE_KEY_PATH)
            ticket_bytes = crypto.rsa_decrypt(server_private_key, encrypted_ticket)
            ticket_data = json.loads(ticket_bytes.decode("utf-8"))

            username = ticket_data["username"]
            session_key = base64.b64decode(ticket_data["session_key"])

            print(f"[App Server] Ticket decrypted successfully!")
            print(f"[App Server] Authenticated user: {username}")
            print(f"[App Server] Session key established (32 bytes AES-256)")

        except Exception as e:
            print(f"[App Server] Ticket decryption FAILED: {e}")
            rpc_protocol.send_message(self.request, rpc_protocol.build_response(
                status="error", message="Invalid ticket — authentication failed"
            ))
            return None, None

        # Send an encrypted ACK back to the client to confirm the handshake
        ack_data = json.dumps({
            "status": "success",
            "message": f"Handshake complete. Welcome, {username}!",
        }).encode("utf-8")
        encrypted_ack = crypto.aes_encrypt(session_key, ack_data)
        rpc_protocol.send_message(self.request, {"encrypted_payload": encrypted_ack})

        print(f"[App Server] Handshake complete with {username}")
        return session_key, username

    def _rpc_loop(self, session_key, username):
        """
        Main RPC loop: receive encrypted requests, execute methods, return encrypted responses.
        
        Args:
            session_key: AES-256 session key for this connection
            username: Authenticated username
        """
        print(f"[App Server] Entering secure RPC loop for {username}...")

        while True:
            # Receive an encrypted RPC request
            message = rpc_protocol.recv_message(self.request)
            if message is None:
                print(f"[App Server] {username} disconnected")
                break

            encrypted_payload = message.get("encrypted_payload", "")

            # Decrypt the request using AES-GCM
            try:
                request_bytes = crypto.aes_decrypt(session_key, encrypted_payload)
                request_data = json.loads(request_bytes.decode("utf-8"))
            except Exception as e:
                print(f"[App Server] Failed to decrypt request from {username}: {e}")
                # Send an encrypted error response
                error_response = json.dumps(rpc_protocol.build_response(
                    status="error", message="Failed to decrypt request"
                )).encode("utf-8")
                encrypted_error = crypto.aes_encrypt(session_key, error_response)
                rpc_protocol.send_message(self.request, {"encrypted_payload": encrypted_error})
                continue

            action = request_data.get("action", "")
            args = request_data.get("args", {})

            print(f"[App Server] RPC call from {username}: {action}({args})")

            # Look up and execute the RPC method
            if action in RPC_METHODS:
                response = RPC_METHODS[action](username, args)
            elif action == "disconnect":
                print(f"[App Server] {username} requested disconnect")
                break
            else:
                response = rpc_protocol.build_response(
                    status="error",
                    message=f"Unknown RPC method: {action}"
                )

            # Encrypt the response and send it back
            response_bytes = json.dumps(response).encode("utf-8")
            encrypted_response = crypto.aes_encrypt(session_key, response_bytes)
            rpc_protocol.send_message(self.request, {"encrypted_payload": encrypted_response})

            print(f"[App Server] Sent encrypted response to {username}")


# =============================================================================
#  Multi-Threaded App Server
# =============================================================================

class ThreadedAppServer(socketserver.ThreadingTCPServer):
    """Multi-threaded TCP server for the E-Wallet Application."""
    allow_reuse_address = True
    daemon_threads = True


def generate_keys_if_needed():
    """Generate App Server RSA keys if they don't exist yet."""
    if not os.path.exists(SERVER_PRIVATE_KEY_PATH) or not os.path.exists(SERVER_PUBLIC_KEY_PATH):
        print("[App Server] Generating RSA key pair...")
        private_key, public_key = crypto.generate_rsa_keypair()
        crypto.save_private_key(private_key, SERVER_PRIVATE_KEY_PATH)
        crypto.save_public_key(public_key, SERVER_PUBLIC_KEY_PATH)
        print(f"[App Server] Keys saved to {KEYS_DIR}")
    else:
        print("[App Server] RSA keys already exist, loading...")


def start_app_server(host=APP_HOST, port=APP_PORT, blocking=True):
    """
    Start the E-Wallet Application Server.
    
    Args:
        host: Hostname to bind to
        port: Port to listen on
        blocking: If True, blocks the calling thread. If False, runs in a background thread.
    
    Returns:
        The server instance (useful for shutdown)
    """
    generate_keys_if_needed()

    server = ThreadedAppServer((host, port), AppRequestHandler)
    print(f"[App Server] Listening on {host}:{port}")
    print(f"[App Server] Ready to accept connections (multi-threaded)")
    print(f"[App Server] Registered RPC methods: {list(RPC_METHODS.keys())}")
    print("=" * 60)

    if blocking:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n[App Server] Shutting down...")
            server.shutdown()
    else:
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

    return server


# =============================================================================
#  Main — Run as standalone server
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("  E-WALLET APPLICATION SERVER")
    print("  Secure E-Wallet System")
    print("=" * 60)
    start_app_server(blocking=True)
