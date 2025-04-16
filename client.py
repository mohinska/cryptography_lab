import socket
import threading
from Crypto.Util.number import getPrime, GCD
import random
import hashlib


def modinv(a, m):
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None


class Client:
    def __init__(self, server_ip: str, port: int, username: str) -> None:
        self.server_ip = server_ip
        self.port = port
        self.username = username
        self.s = None
        self.public_key = None
        self.private_key = None
        self.server_public_key = None

    def init_connection(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.s.connect((self.server_ip, self.port))
        except Exception as e:
            print('[client]: could not connect to server: ', e)
            return

        self.s.send(self.username.encode())

        self.public_key, self.private_key = self.generate_keys()
        print('[client]: my keys are ready')

        pub_key_str = str(self.public_key[0]) + ',' + str(self.public_key[1])
        self.s.send(pub_key_str.encode())
        print('[client]: sent my public key')

        server_key_str = self.s.recv(1024).decode()
        server_key_parts = server_key_str.split(',')
        e = int(server_key_parts[0])
        n = int(server_key_parts[1])
        self.server_public_key = (e, n)
        print('[client]: got server public key')

        message_handler = threading.Thread(target=self.read_handler, args=())
        message_handler.start()
        input_handler = threading.Thread(target=self.write_handler, args=())
        input_handler.start()

    def generate_keys(self):
        p = getPrime(16)
        q = getPrime(16)
        while q == p:
            q = getPrime(16)
        N = p * q
        while True:
            e = random.randint(N//4, N-1)
            if GCD(e, (p-1)*(q-1)) == 1:
                break

        d = modinv(e, (p-1)*(q-1))
        return (e, N), (d, N)

    def decrypt_mes(self, encrypted_message):
        try:
            parts = encrypted_message.split('|')

            if len(parts) != 2:
                return encrypted_message

            hash_value = parts[0]
            encrypted_text = parts[1]

            encrypted_nums = encrypted_text.split(',')
            encrypted_nums = [int(num) for num in encrypted_nums]

            d = self.private_key[0]
            n = self.private_key[1]

            decrypted_chars = []
            for num in encrypted_nums:
                decrypted_num = pow(num, d, n)
                decrypted_char = chr(decrypted_num)
                decrypted_chars.append(decrypted_char)

            decrypted_message = ''.join(decrypted_chars)

            calculated_hash = hashlib.sha256(decrypted_message.encode()).hexdigest()

            if calculated_hash == hash_value:
                return decrypted_message
            return '[WARNING: Message might be tampered] ' + decrypted_message
        except Exception:
            return encrypted_message

    def read_handler(self):
        while True:
            try:
                message = self.s.recv(1024).decode()

                if not message:
                    continue

                decrypted = self.decrypt_mes(message)

                print(decrypted)
            except Exception as e:
                print('[client]: error reading message:', e)

    def encrypt_mes(self, message):
        message_hash = hashlib.sha256(message.encode()).hexdigest()

        e = self.server_public_key[0]
        n = self.server_public_key[1]

        encrypted_nums = []
        for char in message:
            char_num = ord(char)
            encrypted_num = pow(char_num, e, n)
            encrypted_nums.append(str(encrypted_num))

        encrypted_text = ','.join(encrypted_nums)

        result = message_hash + '|' + encrypted_text

        return result

    def write_handler(self):
        while True:
            try:
                message = input()

                if not message:
                    continue

                encrypted = self.encrypt_mes(message)

                self.s.send(encrypted.encode())
            except Exception as e:
                print('[client]: error sending message:', e)


if __name__ == "__main__":
    cl = Client("127.0.0.1", 9001, "b_g")
    cl.init_connection()
