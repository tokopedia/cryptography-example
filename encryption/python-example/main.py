from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

import Crypto
import base64


def main():
    key = "RX9SflncVGx0dZE6qdL3xlfVumWtKmju"  # randomly generated key with length 32 byte
    payload = '{"hello": "world"}'
    pub_key = _get_public_key()
    priv_key = _get_private_key()

    print("=== Testing Encrypt Payload ===")
    print(f"plain payload: {payload}")

    encrypted_payload = encrypt_payload(payload, key)
    print(f"encrypted payload: {encrypted_payload}")

    decrypted_payload = decrypt_payload(encrypted_payload, key)
    print(f"decrypted payload: {decrypted_payload}")

    print("\n=== Testing Encrypt Key ===")
    print(f"plain key: {key}")

    encrypted_key = encrypt_key(key, pub_key)
    print(f"encrypted key: {encrypted_key}")

    decrypted_key = decrypt_key(encrypted_key, priv_key)
    print(f"decrypted key: {decrypted_key}")


def encrypt_payload(payload, key):
    nonce = get_random_bytes(12)
    cipher = AES.new(str.encode(key), AES.MODE_GCM, nonce=nonce)

    ciphertext, tag = cipher.encrypt_and_digest(str.encode(payload))

    return base64.b64encode(ciphertext + tag + nonce)


def decrypt_payload(payload, key):
    decoded = base64.b64decode(payload)

    nonce = decoded[-12:]
    decoded = decoded[:-12]

    tag = decoded[-16:]
    decoded = decoded[:-16]

    cipher = AES.new(str.encode(key), AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(decoded, tag).decode()


def encrypt_key(key, public_key):
    rsa = RSA.importKey(public_key)
    cipher = PKCS1_OAEP.new(rsa, Crypto.Hash.SHA256)
    return base64.b64encode(cipher.encrypt(str.encode(key)))


def decrypt_key(key, private_key):
    rsa = RSA.importKey(private_key)
    cipher = PKCS1_OAEP.new(rsa, Crypto.Hash.SHA256)
    return cipher.decrypt(base64.b64decode(key)).decode()


def _get_public_key():
    with open('../key/pub.pem', 'r') as _file:
        return _file.read()


def _get_private_key():
    with open('../key/priv.pem', 'r') as _file:
        return _file.read()


if __name__ == "__main__":
    main()
