from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto import Random
import base64

message = '{}'
key = RSA.import_key(open('../key/priv.pem').read())
h = SHA256.new(message.encode('utf-8'))
signature = pss.new(key).sign(h)

encodedBytes = base64.b64encode(signature)
encodedStr = str(encodedBytes, "utf-8")
print(encodedStr)

key = RSA.import_key(open('../key/pub.pem').read())
verifier = pss.new(key)
try:
    verifier.verify(h, signature)
    print("The signature is authentic.")
except (ValueError, TypeError):
    print("The signature is not authentic.")
