import struct

MAX_MESSAGE_SIZE = 1024 * 1024  # 1 MiB limit to prevent memory exhaustion


def send_msg(sock, data):
    """Send a message with 4-byte length prefix."""
    length = struct.pack('!I', len(data))
    sock.sendall(length + data)


def recv_msg(sock):
    """Receive a message prefixed with 4-byte length. Returns data or None if connection closed.

    Raises ValueError if the declared length exceeds MAX_MESSAGE_SIZE."""
    raw_length = recv_all(sock, 4)
    if raw_length is None:
        return None
    length = struct.unpack('!I', raw_length)[0]
    if length > MAX_MESSAGE_SIZE:
        raise ValueError(f'message size {length} exceeds limit of {MAX_MESSAGE_SIZE}')
    return recv_all(sock, length)


def recv_all(sock, n):
    """Receive exactly n bytes, returning None if connection closed before getting any."""
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data
