import socket
import threading
from rsa_utils import generate_keys, decrypt, encrypt, sha256_digest


class Client:
    def __init__(self, server_ip, port, username):
        self.server_ip = server_ip
        self.port = port
        self.username = username

    def init_connection(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((self.server_ip, self.port))
        self.s.send(self.username.encode())

        server_pub_data = self.s.recv(4096).decode()
        e_str, n_str = server_pub_data.split("::")
        self.server_pub = (int(e_str), int(n_str))
        self.client_pub, self.client_priv = generate_keys()
        self.s.send(f"{self.client_pub[0]}::{self.client_pub[1]}".encode())

        threading.Thread(target=self.read_handler).start()
        threading.Thread(target=self.write_handler).start()

    def read_handler(self):
        while True:
            try:
                data = self.s.recv(4096).decode()
                msg_hash, encrypted_str = data.split("::")
                encrypted_msg = list(map(int, encrypted_str.split(",")))
                decrypted = decrypt(encrypted_msg, self.client_priv)
                check_hash = sha256_digest(decrypted)
                if msg_hash == check_hash:
                    print("[OK] >", decrypted)
                else:
                    print("[CORRUPTED] >", decrypted)
            except Exception as e:
                print("[ERROR reading]", e)

    def write_handler(self):
        while True:
            text = input()
            msg_hash = sha256_digest(text)
            encrypted = encrypt(text, self.server_pub)
            encrypted_str = ",".join(map(str, encrypted))
            message_str = f"{msg_hash}::{encrypted_str}"
            self.s.send(message_str.encode())


if __name__ == "__main__":
    client = Client("127.0.0.1", 9001, "b_g")
    client.init_connection()
