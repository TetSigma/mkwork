import ecdsa
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

sk = ecdsa.SigningKey.generate()
vk = sk.verifying_key

def encrypt_message(message, public_key):
    aes_key = get_random_bytes(16)

    signature = sk.sign(aes_key)

    cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))

    return aes_key, signature, cipher.nonce, ciphertext, tag

def decrypt_message(aes_key, signature, nonce, ciphertext, tag, private_key):
    try:
        vk.verify(signature, aes_key)
    except ecdsa.BadSignatureError:
        print("Signature verification failed. Message might have been tampered with.")
        return None

    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    decrypted_message = cipher.decrypt_and_verify(ciphertext, tag)

    return decrypted_message.decode('utf-8')

message = "hallo"
print("Original Message:", message)

aes_key, signature, nonce, ciphertext, tag = encrypt_message(message, vk)
print("Encrypted Message:", ciphertext)
decrypted_message = decrypt_message(aes_key, signature, nonce, ciphertext, tag, sk)

print("Decrypted Message:", decrypted_message)

