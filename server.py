import socket
import random
import string
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Допоміжні функції
def generate_random_string(length=32):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# Генерація пари ключів
def generate_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

# Сериалізація публічного ключа
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

# Шифрування повідомлення 
def encrypt_message(message, key):
    return message.encode('utf-8')

# Дешифрування повідомлення 
def decrypt_message(encrypted_message, key):
    return encrypted_message.decode('utf-8')

# Код сервера
def server():
    server_private_key, server_public_key = generate_key_pair()
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind(('localhost', 4000))  # Використовуємо порт 4000
        server_socket.listen(1)
        print("Сервер очікує з'єднання...")
        
        conn, addr = server_socket.accept()
        with conn:
            print(f"Підключено клієнта: {addr}")

            # Крок 2: Відправка "привіт сервера" та публічного ключа
            client_hello = conn.recv(1024).decode('utf-8')
            print(f"Отримано від клієнта: {client_hello}")

            server_hello = "привіт сервера"
            conn.sendall(server_hello.encode('utf-8'))
            conn.sendall(serialize_public_key(server_public_key))
            print(f"Відправлено клієнту: {server_hello} і публічний ключ")

            # Крок 4: Отримання зашифрованого premaster secret і його дешифрування
            encrypted_premaster = conn.recv(1024)
            premaster_secret = server_private_key.decrypt(
                encrypted_premaster,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print(f"Дешифровано premaster secret: {premaster_secret.decode('utf-8')}")

            # Генерація сеансового ключа
            session_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'session key'
            ).derive(premaster_secret)

            # Крок 6: Сервер надсилає "готовий", зашифрований сеансовим ключем
            encrypted_ready = encrypt_message("готовий", session_key)
            conn.sendall(encrypted_ready)
            print("Відправлено зашифроване повідомлення 'готовий'")

            # Встановлено захищене з'єднання
            while True:
                encrypted_data = conn.recv(1024)
                if not encrypted_data:
                    break
                message = decrypt_message(encrypted_data, session_key)
                print(f"Клієнт: {message}")
                response = input("Сервер: ")
                conn.sendall(encrypt_message(response, session_key))

if __name__ == "__main__":
    server()
