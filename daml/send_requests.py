import os
import requests
import json
import time
import csv
import base64
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ─── Generate Keys ────────────────────────────────────────────────────────────
def generate_client_keys():
    """Generate X25519 key pair if missing."""
    if not os.path.exists("client_private_key.pem") or not os.path.exists("client_public_key.pem"):
        print("🔑 Generating new X25519 client key pair...")
        client_private_key = x25519.X25519PrivateKey.generate()
        client_public_key = client_private_key.public_key()

        with open("client_private_key.pem", "wb") as f:
            f.write(client_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        with open("client_public_key.pem", "wb") as f:
            f.write(client_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        print("✅ Keys saved.")

# ─── AES-GCM Encrypt/Decrypt ──────────────────────────────────────────────────
def encrypt_message(plaintext, key):
    try:
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        return nonce, ciphertext, encryptor.tag
    except Exception as e:
        print(f"❌ Encryption error: {e}")
        return None, None, None

def decrypt_message(nonce, ciphertext, tag, key):
    try:
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    except Exception as e:
        print(f"❌ Decryption error: {e}")
        return None

# ─── Init ─────────────────────────────────────────────────────────────────────
generate_client_keys()

with open("client_public_key.pem", "r") as f:
    client_public_key_pem = f.read().strip()

url = "http://127.0.0.1:5000/log_batch_activity"
csv_filename = "execution_results.csv"
file_exists = os.path.isfile(csv_filename)

iot_devices_map = {1: 1, 2: 2, 4: 3, 8: 5, 16: 8, 21: 10}
edge_nodes_map = {1: 1, 2: 1, 4: 2, 8: 3, 16: 4, 21: 5}
test_cases = [1, 2, 4, 8, 16, 21]

with open(csv_filename, "a", newline="", encoding="utf-8") as file:
    writer = csv.writer(file)
    if not file_exists:
        writer.writerow([
            "Test ID", "Message Length", "IoT Devices", "Edge Nodes",
            "KeyGen (ms)", "Sign (ms)", "Validate (ms)", "Sign+Val (ms)",
            "Transmission (ms)", "Decryption (ms)", "Total (ms)", "Encrypted Log"
        ])

    for test_id in test_cases:
        print(f"\n🚀 Running Test {test_id}...")

        num_iot = iot_devices_map.get(test_id, 1)
        num_edge = edge_nodes_map.get(test_id, 1)
        message = os.urandom(test_id * 10)
        message_length = len(message)

        # Key Generation
        t0 = time.time()
        x_priv = x25519.X25519PrivateKey.generate()
        keygen_time = (time.time() - t0) * 1000

        # Sign
        t1 = time.time()
        signer = ed25519.Ed25519PrivateKey.generate()
        signature = signer.sign(message)
        sign_time = (time.time() - t1) * 1000

        # Validate
        t2 = time.time()
        try:
            signer.public_key().verify(signature, message)
            validate_time = (time.time() - t2) * 1000
        except:
            print("❌ Signature verification failed.")
            validate_time = float('nan')

        sign_val_time = sign_time + validate_time

        # Transmission
        t3 = time.time()
        time.sleep(0.005 * test_id)
        transmit_time = (time.time() - t3) * 1000

        # Encrypt
        enc_key = os.urandom(32)
        nonce, ciphertext, tag = encrypt_message(message.decode("utf-8", errors="ignore"), enc_key)
        enc_log = base64.b64encode(ciphertext or b"").decode()

        # Decrypt
        if nonce and ciphertext and tag:
            t4 = time.time()
            decrypted = decrypt_message(nonce, ciphertext, tag, enc_key)
            decrypt_time = (time.time() - t4) * 1000
        else:
            decrypt_time = 0

        total_time = keygen_time + sign_time + validate_time + transmit_time + decrypt_time

        log = {
            "operator_id": "Operator1",
            "operation": f"Test_{test_id}",
            "status": "success",
            "client_public_key": client_public_key_pem,
            "message_length": message_length,
            "execution_time_ms": total_time / 1000,
            "keygen_time_ms": keygen_time / 1000,
            "signcryption_time_ms": sign_time / 1000,
            "validation_time_ms": validate_time / 1000,
            "sign_and_validation_time_ms": sign_val_time / 1000,
            "transmission_time_ms": transmit_time / 1000,
            "decryption_time_ms": decrypt_time / 1000,
            "total_time_ms": total_time / 1000
        }

        try:
            res = requests.post(url, json={"logs": [log]}, headers={"Content-Type": "application/json"})
            data = res.json()

            if isinstance(data.get("processed_logs"), list):
                print("📬 API Response:")
                for plog in data["processed_logs"]:
                    print(f"  ✔ Operator ID: {plog['operator_id']}")
                    print(f"  ✔ Operation:   {plog['operation']}")
                    print(f"  ✔ Status:      {plog['status']}")
                    print(f"  ✔ Public Key:  (truncated) {log['client_public_key'][:40]}...")
                    print(f"  ✔ Message Len: {log['message_length']} bytes")
                    print(f"  ✔ Total Time:  {log['total_time_ms']*1000:.2f} ms")
                    print(f"  ✔ Encrypted:   {enc_log[:30]}...")

                    writer.writerow([
                        test_id, message_length, num_iot, num_edge,
                        keygen_time / 1000, sign_time / 1000, validate_time / 1000,
                        sign_val_time / 1000, transmit_time / 1000, decrypt_time / 1000,
                        total_time / 1000, enc_log
                    ])
                print("✅ Results saved.\n" + "-" * 60)
            else:
                print("❌ API response format incorrect.")
        except Exception as e:
            print(f"❌ Error sending log: {e}")
