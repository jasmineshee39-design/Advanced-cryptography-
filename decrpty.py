import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

def decrypt_message(private_key_path, ciphertext_bytes):
    # 1. Read and load the PEM-formatted private key file
    with open(private_key_path, "rb") as key_file:
        private_key_data = key_file.read()
    
    # 2. Deserialize the key (leave password=None if your key isn't passphrase protected)
    private_key = load_pem_private_key(
        private_key_data,
        password=None # Or provide bytes if encrypted: b"your_passphrase"
    )
    
    # 3. Perform the decryption using OAEP padding matching the encryption process
    plaintext_bytes = private_key.decrypt(
        ciphertext_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # 4. Decode bytes back into a readable string
    return plaintext_bytes.decode('utf-8')

# --- Demonstration / Setup of Mock Data ---
if __name__ == "__main__":
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
    
    print("--- Simulating Key Generation and Encryption ---")
    
    # Generate an ephemeral RSA key pair just for demonstration
    demo_private_key = rsa.generate_private_key(public_key_exponent=65537, key_size=2048)
    demo_public_key = demo_private_key.public_key()
    
    # Save the mock private key to disk in PEM format
    private_key_filename = "private_key.pem"
    with open(private_key_filename, "wb") as f:
        f.write(demo_private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        ))
        
    # Encrypt a secret message using the public key to create our test payload
    secret_message = "Confidential: Access Granted to Project Alpha."
    encrypted_payload = demo_public_key.encrypt(
        secret_message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"Encrypted Bytes (Ciphertext):\n{encrypted_payload.hex()[:60]}...\n")

    # --- Executing the Decryption Phase ---
    print("--- Executing Private Key Decryption ---")
    try:
        decrypted_text = decrypt_message(private_key_filename, encrypted_payload)
        print(f"Decryption Successful!")
        print(f"Decrypted Message: '{decrypted_text}'")
    except Exception as e:
        print(f"Decryption Failed: {e}")
        
    # Clean up file
    if os.path.exists(private_key_filename):
        os.remove(private_key_filename)