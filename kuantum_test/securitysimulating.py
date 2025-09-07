from qiskit import QuantumCircuit, Aer
import random

key_length = 10

alice_bits = [random.choice([0, 1]) for _ in range(key_length)]
alice_bases = [random.choice([0, 1]) for _ in range(key_length)]

bob_bases = [random.choice([0, 1]) for _ in range(key_length)]

qc = QuantumCircuit(key_length, key_length)

for i in range(key_length):
    if alice_bits[i] == 1:
        qc.x(i)
    if alice_bases[i] == 1:
        qc.h(i)

qc.measure(range(key_length), range(key_length))

simulator = Aer.get_backend('qasm_simulator')
result = execute(qc, simulator, shots=1).result()
bob_results = list(result.get_counts().keys())[0]
bob_bits = [int(bit) for bit in bob_results[::-1]]

shared_key = [alice_bits[i] for i in range(key_length) if alice_bases[i] == bob_bases[i]]
print("BB84 Protokolü Anahtarı:", shared_key)

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from os import urandom
from hashlib import sha256

ses_key = sha256(bytes(shared_key)).digest()

Cipher = Cipher(algorithms.AES(ses_key), modes.CBC(iv), backend=default_backend())

padder = padding.PKCS7(128).padder()
plaintext = "Bu bir test mesajıdır.".encode()

padded_data = padder.update(plaintext) + padder.finalize()
encryptor = Cipher.encryptor()

ciphertext = encryptor.update(padded_data) + encryptor.finalize()
print("AES ile Şifrelenmiş Veri:", ciphertext)

decryptor = Cipher.decryptor()
decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()

unpadder = padding.PKCS7(128).unpadder()
decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

print("Çözülen Veri:", decrypted_data.decode())

from itertools import product
import time

def brute_force_aes(ciphertext, iv):
    start_time = time.time()
    possible_keys = product([0, 1], repeat=8)

    for key_bits in possible_keys:
        key = bytes(key_bits * 4)
        iv = urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

brute_force_aes(ciphertext, iv)

eve_bases = [random.choice([0, 1]) for _ in range(key_length)]
intercepted_key = [alice_bits[i] for i in range(key_length) if alice_bases[i] == eve_bases[i]]

if intercepted_key == shared_key:
    print("Eve BB84 anahtarını başarıyla ele geçirdi!")
else:
    print("Eve BB84 anahtarını ele geçiremedi, kuantum şifreleme güvenli!")