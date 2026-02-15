import time
import oqs
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# A dummy 32-byte secret to lock in the classical box
SECRET_MESSAGE = b"my_super_secret_aes_key_32_bytes" 

def benchmark_rsa():
    print("--- Running Classical RSA-2048 Benchmark ---")
    
    # 1. TIME KEY GENERATION
    start = time.perf_counter()
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    rsa_keygen_time = time.perf_counter() - start
    
    # 2. TIME ENCRYPTION (Locking the box)
    start = time.perf_counter()
    ciphertext = public_key.encrypt(
        SECRET_MESSAGE,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    rsa_enc_time = time.perf_counter() - start
    
    # 3. TIME DECRYPTION (Opening the box)
    start = time.perf_counter()
    decrypted_message = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    rsa_dec_time = time.perf_counter() - start

    return rsa_keygen_time, rsa_enc_time, rsa_dec_time

def benchmark_ml_kem():
    print("--- Running Quantum ML-KEM-512 Benchmark ---")
    kem_name = "ML-KEM-512"
    
    with oqs.KeyEncapsulation(kem_name) as kem:
        # 1. TIME KEY GENERATION
        start = time.perf_counter()
        public_key = kem.generate_keypair()
        kem_keygen_time = time.perf_counter() - start
        
        # 2. TIME ENCAPSULATION (Locking the box)
        start = time.perf_counter()
        ciphertext, shared_secret = kem.encap_secret(public_key)
        kem_enc_time = time.perf_counter() - start
        
        # 3. TIME DECAPSULATION (Opening the box)
        start = time.perf_counter()
        decrypted_secret = kem.decap_secret(ciphertext)
        kem_dec_time = time.perf_counter() - start
        
    return kem_keygen_time, kem_enc_time, kem_dec_time

if __name__ == "__main__":
    print("Initializing Benchmark Protocol...\n")
    
    # Run the races
    rsa_times = benchmark_rsa()
    kem_times = benchmark_ml_kem()
    
    # Print the Executive Report
    print("\n=======================================================")
    print("      EXECUTIVE PERFORMANCE REPORT (Latency in ms)       ")
    print("=======================================================")
    print(f"{'Operation':<20} | {'RSA-2048 (Classical)':<20} | {'ML-KEM-512 (Quantum)'}")
    print("-" * 65)
    print(f"{'Key Generation':<20} | {rsa_times[0]*1000:<20.3f} | {kem_times[0]*1000:.3f}")
    print(f"{'Encapsulation':<20} | {rsa_times[1]*1000:<20.3f} | {kem_times[1]*1000:.3f}")
    print(f"{'Decapsulation':<20} | {rsa_times[2]*1000:<20.3f} | {kem_times[2]*1000:.3f}")
    print("=======================================================\n")
    
    print("Note: Lower numbers are better (faster).")