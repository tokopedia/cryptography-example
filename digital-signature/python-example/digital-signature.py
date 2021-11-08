from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import base64

message = '{}'
message_bytes = message.encode('utf-8')
h = SHA256.new(message_bytes)

key = RSA.import_key(open('../key/priv.pem').read())
l = int(key.n.bit_length() / 8) - h.digest_size-2
signature = pss.new(key, salt_bytes=l).sign(h)

encodedBytes = base64.b64encode(signature)
encodedStr = str(encodedBytes, "utf-8")
print(encodedStr)

key = RSA.import_key(open('../key/pub.pem').read())
verifier = pss.new(key, salt_bytes=l)
try:
    verifier.verify(h, signature)
    print("The signature is authentic.")
except (ValueError, TypeError):
    print("The signature is NOT authentic.")
