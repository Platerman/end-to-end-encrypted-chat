import socket
import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from base64 import urlsafe_b64encode

from utils import send_msg, recv_msg, MAX_MESSAGE_SIZE

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5500


def main():
    sock = None
    client = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((SERVER_HOST, SERVER_PORT))
        except OSError as e:
            print(f'Failed to bind {SERVER_HOST}:{SERVER_PORT} – {e}')
            return
        sock.listen(5)

        print(f'Running in {SERVER_HOST}:{SERVER_PORT}\n')
        print('- Wait connection...')

        client, __ = sock.accept()
        print('- Connected, deriving key...')

        # Pre-shared key: ask for password
        shared_password = ''
        while not shared_password:
            shared_password = getpass.getpass('Enter shared password: ').strip()
            if not shared_password:
                print('Password cannot be empty.')
        # Derive a 32-byte key using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'chat-key',
        )
        key = hkdf.derive(shared_password.encode())
        fernet = Fernet(urlsafe_b64encode(key), ttl=None)
        print('- Key derived successfully.\n')

        print('=' * 20)

        while True:
            # wait for client message
            try:
                client_msg = recv_msg(client)
            except ValueError as e:
                print(f'- Protocol error: {e}')
                break
            if client_msg is None:
                print('- Client disconnected.')
                break
            try:
                client_msg_decrypted = fernet.decrypt(client_msg)
                print(f'client> {client_msg_decrypted.decode()}')
            except Exception as e:
                print(f'- Decryption error: {e}')
                break

            message = input('message> ').strip()
            encrypted_msg = fernet.encrypt(message.encode())
            send_msg(client, encrypted_msg)
            print('...')

    except KeyboardInterrupt:
        print('Bye.')
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError) as e:
        print(f'- Connection error: {e}')
    finally:
        if client:
            client.close()
        if sock:
            sock.close()


main()
