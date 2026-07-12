import socket
import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from base64 import urlsafe_b64encode

from utils import send_msg, recv_msg, MAX_MESSAGE_SIZE


def main():
    host = input('Host to connect: ').strip()
    while True:
        try:
            port = int(input('Port to connect: ').strip())
            break
        except ValueError:
            print('Invalid port, please enter a number.')

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))

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
        print('- Key derived successfully.')

        print('=' * 20)

        while True:
            message = input('message> ').strip()
            encrypted_msg = fernet.encrypt(message.encode())
            send_msg(sock, encrypted_msg)
            print('...')

            # wait response
            try:
                response = recv_msg(sock)
            except ValueError as e:
                print(f'- Protocol error: {e}')
                break
            if response is None:
                print('- Server disconnected.')
                break
            try:
                response_decrypted = fernet.decrypt(response)
                print(f'server> {response_decrypted.decode()}')
            except Exception as e:
                print(f'- Decryption error: {e}')
                break

    except ConnectionRefusedError:
        print(f'Connection refused by {host}:{port}. Is the server running?')
    except KeyboardInterrupt:
        print('Bye.')
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError) as e:
        print(f'- Connection error: {e}')
    finally:
        if sock:
            sock.close()


main()
