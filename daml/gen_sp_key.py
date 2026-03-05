from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
# generate keypair
sk = ed25519.Ed25519PrivateKey.generate()
pk = sk.public_key()
# save private key (PEM, no password)
pem = sk.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
open("sp_ed25519_priv.pem","wb").write(pem)
# print & save public key hex (64 hex chars)
pk_hex = pk.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
).hex()
open("sp_ed25519_pub.hex","w").write(pk_hex)
print(pk_hex)
