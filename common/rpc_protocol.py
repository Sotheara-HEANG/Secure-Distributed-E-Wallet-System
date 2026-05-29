"""
rpc_protocol.py — Custom RPC Protocol over TCP
=================================================
Implements length-prefixed JSON message framing for reliable
communication over TCP sockets.

Message Format on the wire:
  [4-byte big-endian length][JSON payload or raw bytes]

This ensures the receiver knows exactly how many bytes to read,
which is critical because TCP is a stream protocol (no built-in
message boundaries).
"""

import json
import struct


# Maximum message size: 16 MB (safety limit to prevent memory exhaustion)
MAX_MESSAGE_SIZE = 16 * 1024 * 1024


def send_message(sock, data_dict):
    """
    Serialize a Python dictionary to JSON and send it over a TCP socket
    with a 4-byte length prefix.
    
    Args:
        sock: Connected TCP socket
        data_dict: Dictionary to send (must be JSON-serializable)
    """
    json_bytes = json.dumps(data_dict).encode("utf-8")
    length = len(json_bytes)
    
    if length > MAX_MESSAGE_SIZE:
        raise ValueError(f"Message too large: {length} bytes (max: {MAX_MESSAGE_SIZE})")
    
    # Pack the length as a 4-byte big-endian unsigned integer
    header = struct.pack("!I", length)
    
    # Send header + payload
    sock.sendall(header + json_bytes)


def recv_message(sock):
    """
    Receive a length-prefixed JSON message from a TCP socket and
    deserialize it into a Python dictionary.
    
    Args:
        sock: Connected TCP socket
    
    Returns:
        dict: Deserialized message, or None if connection closed
    """
    # Read the 4-byte length header
    header = _recv_exact(sock, 4)
    if header is None:
        return None
    
    # Unpack the length
    length = struct.unpack("!I", header)[0]
    
    if length > MAX_MESSAGE_SIZE:
        raise ValueError(f"Message too large: {length} bytes (max: {MAX_MESSAGE_SIZE})")
    
    # Read exactly `length` bytes of payload
    json_bytes = _recv_exact(sock, length)
    if json_bytes is None:
        return None
    
    return json.loads(json_bytes.decode("utf-8"))


def send_raw(sock, raw_bytes):
    """
    Send raw bytes over a TCP socket with a 4-byte length prefix.
    Used for sending encrypted payloads that are not JSON.
    
    Args:
        sock: Connected TCP socket
        raw_bytes: Raw bytes to send
    """
    length = len(raw_bytes)
    
    if length > MAX_MESSAGE_SIZE:
        raise ValueError(f"Message too large: {length} bytes (max: {MAX_MESSAGE_SIZE})")
    
    header = struct.pack("!I", length)
    sock.sendall(header + raw_bytes)


def recv_raw(sock):
    """
    Receive raw bytes from a TCP socket with a 4-byte length prefix.
    Used for receiving encrypted payloads.
    
    Args:
        sock: Connected TCP socket
    
    Returns:
        bytes: Raw received bytes, or None if connection closed
    """
    header = _recv_exact(sock, 4)
    if header is None:
        return None
    
    length = struct.unpack("!I", header)[0]
    
    if length > MAX_MESSAGE_SIZE:
        raise ValueError(f"Message too large: {length} bytes (max: {MAX_MESSAGE_SIZE})")
    
    return _recv_exact(sock, length)


def _recv_exact(sock, num_bytes):
    """
    Helper: Read exactly `num_bytes` from a TCP socket.
    
    TCP is a stream protocol — a single recv() call may return fewer
    bytes than requested. This function loops until all bytes are received.
    
    Args:
        sock: Connected TCP socket
        num_bytes: Exact number of bytes to read
    
    Returns:
        bytes: Exactly `num_bytes` of data, or None if connection closed
    """
    data = b""
    while len(data) < num_bytes:
        chunk = sock.recv(num_bytes - len(data))
        if not chunk:
            # Connection was closed by the other side
            return None
        data += chunk
    return data


# =============================================================================
#  Helper: Build standard RPC request and response dictionaries
# =============================================================================

def build_request(action, **kwargs):
    """
    Build a standard RPC request dictionary.
    
    Args:
        action: The remote procedure name (e.g., "deposit", "withdraw")
        **kwargs: Arguments for the procedure
    
    Returns:
        dict: {"action": "deposit", "args": {"amount": 500.0}}
    """
    return {
        "action": action,
        "args": kwargs,
    }


def build_response(status="success", data=None, message=None):
    """
    Build a standard RPC response dictionary.
    
    Args:
        status: "success" or "error"
        data: Response data dictionary (on success)
        message: Error message string (on error)
    
    Returns:
        dict: {"status": "success", "data": {...}} or {"status": "error", "message": "..."}
    """
    response = {"status": status}
    if data is not None:
        response["data"] = data
    if message is not None:
        response["message"] = message
    return response
