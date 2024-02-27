from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from base64 import urlsafe_b64encode, urlsafe_b64decode
import getpass
import os

def generate_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,  # Ajuste o número de iterações conforme necessário
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))
    return key

def encrypt_message(key, message):
    key = urlsafe_b64decode(key)
    cipher = Cipher(algorithms.AES(key), modes.GCM(), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
    tag = encryptor.tag
    nonce = encryptor.nonce
    return urlsafe_b64encode(nonce + tag + ciphertext)

def decrypt_message(key, encrypted_message):
    key = urlsafe_b64decode(key)
    decoded_message = urlsafe_b64decode(encrypted_message)
    nonce = decoded_message[:12]
    tag = decoded_message[12:28]
    ciphertext = decoded_message[28:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_message.decode('utf-8')

def generate_key_pair():
    # Gere uma chave aleatória para a senha (para fins de exemplo)
    senha_secreta = getpass.getpass("Digite sua senha: ")

    # Gere um "salt" aleatório para cada usuário (deve ser armazenado junto com a senha no mundo real)
    salt = os.urandom(16)

    # Gere a chave a partir da senha e do "salt"
    chave_secreta = generate_key_from_password(senha_secreta, salt)

    # Agora você pode usar essa chave para criptografar e descriptografar mensagens

    # Se você quiser armazenar a chave de maneira segura para uso futuro, você pode criptografá-la usando outra chave mestra
    # que é derivada da senha do usuário.
    senha_mestra = getpass.getpass("Digite sua senha mestra: ")
    chave_mestra = generate_key_from_password(senha_mestra, salt)

    # Criptografe a chave secreta usando a chave mestra
    chave_secreta_cifrada = encrypt_message(chave_mestra, chave_secreta)

    # Agora você pode armazenar a chave_secreta_cifrada em um local seguro

    # Para recuperar a chave_secreta original, você pode descriptografá-la usando a chave mestra
    chave_secreta_recuperada = decrypt_message(chave_mestra, chave_secreta_cifrada)

    return chave_secreta, chave_secreta_recuperada

# Exemplo de uso:
mensagem_original = "Esta é uma mensagem confidencial."

# Gere um par de chaves
chave_secreta, chave_secreta_recuperada = generate_key_pair()

# Criptografe a mensagem
mensagem_criptografada = encrypt_message(chave_secreta, mensagem_original)
print("Mensagem Criptografada:", mensagem_criptografada)

# Decifre a mensagem
mensagem_decifrada = decrypt_message(chave_secreta_recuperada, mensagem_criptografada)
print("Mensagem Decifrada:", mensagem_decifrada)
