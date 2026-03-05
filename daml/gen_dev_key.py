from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization as s

sk = x25519.X25519PrivateKey.generate()
open("dev1_x25519_priv.pem","wb").write(
    sk.private_bytes(encoding=s.Encoding.PEM,
                     format=s.PrivateFormat.PKCS8,
                     encryption_algorithm=s.NoEncryption())
)
pk_hex = sk.public_key().public_bytes(
    encoding=s.Encoding.Raw, format=s.PublicFormat.Raw
).hex()
open("dev1_x25519_pub.hex","w").write(pk_hex)
print(pk_hex)
