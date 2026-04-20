from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS



key = ECC.generate(curve="P-256")

message = "This is a secret message."
hash_msg = SHA256.new(message.encode())

signer = DSS.new(key, "fips-186-3")
signature = signer.sign(hash_msg)

print("Message:", message)
print("Signature:", signature.hex())


verifier = DSS.new(key.public_key(), "fips-186-3")

try:
    verifier.verify(hash_msg, signature)
    print("Signature is valid.")
except ValueError:
    print("Signature is invalid.")