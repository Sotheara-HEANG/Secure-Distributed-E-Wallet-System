"""
auth_server.py — Authentication Service
==========================================
A multi-threaded TCP server that handles:
  1. User registration (username + password)
  2. User login with RSA-encrypted session key distribution
  3. Ticket generation for the App Server

Runs on port 8001 by default.

Security Flow:
  - Passwords are hashed with SHA-256 before storage (never stored in plaintext)
  - On login, generates a random AES-256 session key
  - Session key is encrypted with the Client's RSA public key
  - A Ticket (containing username + session key) is encrypted with the App Server's RSA public key
  - Only the Client can decrypt the session key; only the App Server can decrypt the ticket
"""

import os
import sys
import json
import hashlib
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

AUTH_HOST = "127.0.0.1"
AUTH_PORT = 8001

# Key file paths (relative to project root)
PROJECT_ROOT = os.path.join(os.path.dirname(__file__), "..")
KEYS_DIR = os.path.join(PROJECT_ROOT, "keys")
AUTH_PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "auth_private.pem")
AUTH_PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "auth_public.pem")
SERVER_PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "server_public.pem")


# =============================================================================
#  In-Memory User Database (thread-safe)
# =============================================================================

user_db = {}          # { username: hashed_password }
user_db_lock = threading.Lock()


def hash_password(password):
    """Hash a password using SHA-256."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


# =============================================================================
#  Auth Service Request Handler
# =============================================================================

class AuthRequestHandler(socketserver.BaseRequestHandler):
    """
    Handles a single client connection to the Auth Service.
    Each connection is processed in its own thread by ThreadingTCPServer.
    """

    def handle(self):
        """Process incoming authentication requests from a client."""
        client_addr = self.client_address
        print(f"[Auth Service] New connection from {client_addr}")

        try:
            # Receive the client's request
            message = rpc_protocol.recv_message(self.request)
            if message is None:
                return

            action = message.get("action")
            args = message.get("args", {})

            print(f"[Auth Service] Action: {action} from {client_addr}")

            if action == "get_public_key":
                self._handle_get_public_key()
            elif action == "register":
                self._handle_register(args)
            elif action == "login":
                self._handle_login(args)
            else:
                response = rpc_protocol.build_response(
                    status="error",
                    message=f"Unknown action: {action}"
                )
                rpc_protocol.send_message(self.request, response)

        except Exception as e:
            print(f"[Auth Service] Error handling {client_addr}: {e}")
            try:
                response = rpc_protocol.build_response(
                    status="error",
                    message=f"Internal server error: {str(e)}"
                )
                rpc_protocol.send_message(self.request, response)
            except Exception:
                pass

        print(f"[Auth Service] Connection from {client_addr} closed")

    def _handle_get_public_key(self):
        """Return the Auth Service's public key to the client."""
        auth_public_key = crypto.load_public_key(AUTH_PUBLIC_KEY_PATH)
        pem_string = crypto.serialize_public_key(auth_public_key)

        response = rpc_protocol.build_response(
            status="success",
            data={"public_key": pem_string}
        )
        rpc_protocol.send_message(self.request, response)
        print("[Auth Service] Sent public key to client")

    def _handle_register(self, args):
        """Register a new user with username and password."""
        username = args.get("username", "").strip()
        password = args.get("password", "").strip()

        if not username or not password:
            response = rpc_protocol.build_response(
                status="error",
                message="Username and password are required"
            )
            rpc_protocol.send_message(self.request, response)
            return

        with user_db_lock:
            if username in user_db:
                response = rpc_protocol.build_response(
                    status="error",
                    message=f"User '{username}' already exists"
                )
                rpc_protocol.send_message(self.request, response)
                return

            # Hash the password and store it
            user_db[username] = hash_password(password)

        print(f"[Auth Service] Registered new user: {username}")
        response = rpc_protocol.build_response(
            status="success",
            data={"message": f"User '{username}' registered successfully"}
        )
        rpc_protocol.send_message(self.request, response)

    def _handle_login(self, args):
        """
        Authenticate a user and issue a session key + server ticket.
        
        Steps:
          1. Verify username and password
          2. Generate a random AES-256 session key
          3. Encrypt session key with Client's RSA public key
          4. Create a Ticket (username + session key) encrypted with App Server's RSA public key
          5. Return both encrypted payloads to the client
        """
        username = args.get("username", "").strip()
        password = args.get("password", "").strip()
        client_public_key_pem = args.get("client_public_key", "")

        # Step 1: Verify credentials
        with user_db_lock:
            stored_hash = user_db.get(username)

        if stored_hash is None or stored_hash != hash_password(password):
            response = rpc_protocol.build_response(
                status="error",
                message="Invalid username or password"
            )
            rpc_protocol.send_message(self.request, response)
            print(f"[Auth Service] Login FAILED for user: {username}")
            return

        print(f"[Auth Service] Credentials verified for user: {username}")

        # Step 2: Generate a random AES-256 session key
        session_key = crypto.generate_session_key()
        print(f"[Auth Service] Generated session key (32 bytes) for {username}")

        # Step 3: Encrypt the session key with the Client's RSA public key
        client_public_key = crypto.deserialize_public_key(client_public_key_pem)
        encrypted_session_key = crypto.rsa_encrypt(client_public_key, session_key)
        print(f"[Auth Service] Encrypted session key with Client's public key")

        # Step 4: Create a Ticket and encrypt it with the App Server's RSA public key
        ticket_data = json.dumps({
            "username": username,
            "session_key": base64.b64encode(session_key).decode("utf-8"),
        }).encode("utf-8")

        server_public_key = crypto.load_public_key(SERVER_PUBLIC_KEY_PATH)
        encrypted_ticket = crypto.rsa_encrypt(server_public_key, ticket_data)
        print(f"[Auth Service] Created ticket and encrypted with App Server's public key")

        # Step 5: Send both encrypted payloads back to the client
        response = rpc_protocol.build_response(
            status="success",
            data={
                "encrypted_session_key": encrypted_session_key,
                "encrypted_ticket": encrypted_ticket,
                "message": f"Login successful for '{username}'"
            }
        )
        rpc_protocol.send_message(self.request, response)
        print(f"[Auth Service] Login SUCCESS — sent session key + ticket to {username}")


# =============================================================================
#  Multi-Threaded Auth Server
# =============================================================================

class ThreadedAuthServer(socketserver.ThreadingTCPServer):
    """Multi-threaded TCP server for the Authentication Service."""
    allow_reuse_address = True
    daemon_threads = True


def generate_keys_if_needed():
    """Generate Auth Service RSA keys if they don't exist yet."""
    if not os.path.exists(AUTH_PRIVATE_KEY_PATH) or not os.path.exists(AUTH_PUBLIC_KEY_PATH):
        print("[Auth Service] Generating RSA key pair...")
        private_key, public_key = crypto.generate_rsa_keypair()
        crypto.save_private_key(private_key, AUTH_PRIVATE_KEY_PATH)
        crypto.save_public_key(public_key, AUTH_PUBLIC_KEY_PATH)
        print(f"[Auth Service] Keys saved to {KEYS_DIR}")
    else:
        print("[Auth Service] RSA keys already exist, loading...")


def start_auth_server(host=AUTH_HOST, port=AUTH_PORT, blocking=True):
    """
    Start the Authentication Service.
    
    Args:
        host: Hostname to bind to
        port: Port to listen on
        blocking: If True, blocks the calling thread. If False, runs in a background thread.
    
    Returns:
        The server instance (useful for shutdown)
    """
    generate_keys_if_needed()

    server = ThreadedAuthServer((host, port), AuthRequestHandler)
    print(f"[Auth Service] Listening on {host}:{port}")
    print(f"[Auth Service] Ready to accept connections (multi-threaded)")
    print("=" * 60)

    if blocking:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n[Auth Service] Shutting down...")
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
    print("  AUTHENTICATION SERVICE")
    print("  Secure E-Wallet System")
    print("=" * 60)
    start_auth_server(blocking=True)
