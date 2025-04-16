import socket
import threading
from rsa_utils import generate_keys, encrypt, decrypt, sha256_digest


class Server:
    def __init__(self, port):
        self.host = '127.0.0.1'
        self.port = port
        self.clients = []
        self.usernames = {}
        self.public_keys = {}
        self.server_pub, self.server_priv = generate_keys()
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start(self):
        self.s.bind((self.host, self.port))
        self.s.listen(10)
        print("[server] Running...")

        while True:
            client, addr = self.s.accept()
            username = client.recv(1024).decode()
            self.usernames[client] = username
            self.clients.append(client)

            # Відправити публічний ключ сервера
            server_pub_str = f"{self.server_pub[0]}::{self.server_pub[1]}"
            client.send(server_pub_str.encode())
            # Отримати публічний ключ клієнта
            server_pub_data = client.recv(4096).decode()
            e_str, n_str = server_pub_data.split("::")
            self.public_keys[client] = (int(e_str), int(n_str))

            print(f"[server] {username} connected")
            threading.Thread(target=self.handle_client, args=(client,)).start()

    def handle_client(self, c):
        while True:
            try:
                data = c.recv(4096).decode()
                msg_hash, encrypted_str = data.split("::")
                encrypted_msg = list(map(int, encrypted_str.split(",")))
                decrypted_msg = decrypt(encrypted_msg, self.server_priv)
                valid = sha256_digest(decrypted_msg) == msg_hash

                username = self.usernames[c]
                output = f"{username}: {decrypted_msg}"
                if not valid:
                    output = f"{username}: [tampered] {decrypted_msg}"

                self.broadcast(output, sender=c)

            except Exception as e:
                print("[server error]", e)
                c.close()
                self.clients.remove(c)
                break

    def broadcast(self, msg, sender):
        for client in self.clients:
            if client == sender:
                continue
            encrypted = encrypt(msg, self.public_keys[client])
            msg_hash = sha256_digest(msg)
            encrypted_str = ",".join(map(str, encrypted))
            message_str = f"{msg_hash}::{encrypted_str}"
            client.send(message_str.encode())


if __name__ == "__main__":
    Server(9001).start()
