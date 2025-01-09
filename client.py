import socket
import random
import string
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Допоміжні функції
def generate_random_string(length=32):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# Десериалізація публічного ключа
def deserialize_public_key(public_key_bytes):
    return serialization.load_pem_public_key(public_key_bytes)

# Шифрування повідомлення 
def encrypt_message(message, key):
    return message.encode('utf-8')

# Дешифрування повідомлення 
def decrypt_message(encrypted_message, key):
    return encrypted_message.decode('utf-8')

# Код клієнта
def client():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect(('localhost', 4000))  # Використовуємо порт 4000

        # Крок 1: Клієнт надсилає "привіт"
        client_hello = "привіт"
        client_socket.sendall(client_hello.encode('utf-8'))
        print(f"Відправлено серверу: {client_hello}")

        # Крок 2: Отримання "привіт сервера" та публічного ключа
        server_hello = client_socket.recv(1024).decode('utf-8')
        print(f"Отримано від сервера: {server_hello}")

        server_public_key_bytes = client_socket.recv(1024)
        server_public_key = deserialize_public_key(server_public_key_bytes)
        print("Отримано публічний ключ сервера")

        # Крок 4: Генерація та відправка зашифрованого premaster secret
        premaster_secret = generate_random_string().encode('utf-8')
        encrypted_premaster = server_public_key.encrypt(
            premaster_secret,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        client_socket.sendall(encrypted_premaster)
        print(f"Відправлено зашифрований premaster secret")

        # Генерація сеансового ключа
        session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'session key'
        ).derive(premaster_secret)

        # Крок 6: Отримання зашифрованого "готовий" від сервера
        encrypted_ready = client_socket.recv(1024)
        ready_message = decrypt_message(encrypted_ready, session_key)
        print(f"Сервер: {ready_message}")

        # Встановлено захищене з'єднання
        while True:
            message = input("Клієнт: ")
            client_socket.sendall(encrypt_message(message, session_key))
            encrypted_response = client_socket.recv(1024)
            response = decrypt_message(encrypted_response, session_key)
            print(f"Сервер: {response}")

if __name__ == "__main__":
    client()
