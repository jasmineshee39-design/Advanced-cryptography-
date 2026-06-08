import time
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

def benchmark_cipher(cipher_name, cipher_instance, data):
    """Measures the encryption time and calculates throughput."""
    # Generate a standard 12-byte nonce/IV for AEAD ciphers
    nonce = os.urandom(12)
    
    # Warm-up run to ensure functions are cached/compiled in memory
    cipher_instance.encrypt(nonce, data[:1024], None)
    
    # Start timing
    start_time = time.perf_counter()
    
    # Perform the encryption
    ciphertext = cipher_instance.encrypt(nonce, data, None)
    
    # End timing
    end_time = time.perf_counter()
    
    execution_time = end_time - start_time
    data_size_mb = len(data) / (1024 * 1024)
    throughput = data_size_mb / execution_time
    
    print(f"=== {cipher_name} Performance ===")
    print(f"Data Size:        {data_size_mb:.2f} MB")
    print(f"Encryption Time:  {execution_time:.6f} seconds")
    print(f"Throughput:       {throughput:.2f} MB/s\n")
    
    return execution_time, throughput

if __name__ == "__main__":
    print("Initializing Encryption Performance Test...\n")
    
    # 1. Generate 10 MB of random bytes to encrypt
    data_to_encrypt = os.urandom(10 * 1024 * 1024) 
    
    # 2. Setup AES-GCM (256-bit key)
    aes_key = AESGCM.generate_key(bit_length=256)
    aes_instance = AESGCM(aes_key)
    
    # 3. Setup ChaCha20-Poly1305
    chacha_key = ChaCha20Poly1305.generate_key()
    chacha_instance = ChaCha20Poly1305(chacha_key)
    
    # 4. Run Benchmarks
    benchmark_cipher("AES-256-GCM", aes_instance, data_to_encrypt)
    benchmark_cipher("ChaCha20-Poly1305", chacha_instance, data_to_encrypt)