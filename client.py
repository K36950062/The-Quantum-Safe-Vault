import socket
import oqs
import os
import json
import time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# --- CONFIGURATION ---
HOST = '127.0.0.1'
PORT = 1337
KEM_ALG = "ML-KEM-512"
SIG_ALG = "ML-DSA-44"

def derive_hybrid_key(quantum_secret, classical_secret):
    """Combines Quantum and Classical secrets into one AES-256 key."""
    combined_material = quantum_secret + classical_secret
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"v3-hybrid-chat",
    ).derive(combined_material)

def encrypt_message(key, plaintext):
    """Encrypts a message using AES-256-GCM."""
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
    ).encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return iv + encryptor.tag + ciphertext

def decrypt_message(key, payload):
    """Decrypts a message using AES-256-GCM."""
    iv = payload[:12]
    tag = payload[12:28]
    ciphertext = payload[28:]
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def start_client():
    print(f"--- 2. ALICE (CLIENT) STARTING UP ---")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print(f"[*] Connecting to {HOST}:{PORT}...")
        try:
            s.connect((HOST, PORT))
        except ConnectionRefusedError:
            print("[-] Connection failed. Is the server running?")
            return

        # --- STEP A: RECEIVE HANDSHAKE BUNDLE ---
        # Read line (newline delimited JSON)
        file_obj = s.makefile('rb') 
        data = file_obj.readline()
        bundle = json.loads(data.decode())
        
        pub_sig_bytes = bytes.fromhex(bundle['pub_sig'])
        pub_kem_bytes = bytes.fromhex(bundle['pub_kem'])
        pub_ec_bytes = bytes.fromhex(bundle['pub_ec'])
        signature = bytes.fromhex(bundle['signature'])
        
        # --- STEP B: VERIFY SERVER IDENTITY ---
        print("[*] Verifying Bob's Digital Signature...")
        sid_sig = oqs.Signature(SIG_ALG)
        
        # We verify that (Quantum_Pub + Classical_Pub) was signed by Bob
        data_to_verify = pub_kem_bytes + pub_ec_bytes
        is_valid = sid_sig.verify(data_to_verify, signature, pub_sig_bytes)
        
        if is_valid:
            print("[+] SIGNATURE VALID! Identify Verified.")
        else:
            print("[-] SIGNATURE INVALID! Man-in-the-Middle Detected!")
            return

        # --- STEP C: HYBRID ENCAPSULATION ---
        print("[*] Performing Hybrid Encapsulation...")
        
        # 1. Quantum Encapsulation (KEM)
        sid_kem = oqs.KeyEncapsulation(KEM_ALG)
        ciphertext, shared_secret_quantum = sid_kem.encap_secret(pub_kem_bytes)
        
        # 2. Classical Key Exchange (ECDHE)
        # Alice generates her ephemeral keypair
        priv_ec = ec.generate_private_key(ec.SECP256R1())
        pub_ec = priv_ec.public_key()
        alice_pub_ec_bytes = pub_ec.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Compute classical secret using Bob's public key
        bob_pub_ec = serialization.load_pem_public_key(pub_ec_bytes)
        shared_secret_classical = priv_ec.exchange(ec.ECDH(), bob_pub_ec)
        
        # --- STEP D: SEND RESPONSE ---
        response = {
            "kem_ciphertext": ciphertext.hex(),
            "pub_ec": alice_pub_ec_bytes.hex()
        }
        s.sendall(json.dumps(response).encode())
        
        # --- STEP E: DERIVE HYBRID KEY ---
        session_key = derive_hybrid_key(shared_secret_quantum, shared_secret_classical)
        print("[+] SECURE CONNECTION ESTABLISHED!")
        
        # --- STEP F: CHAT LOOP ---
        print("\n--- CHAT SESSION STARTED (Type 'exit' to quit) ---")
        while True:
            # Alice speaks first usually, or we can make it async. 
            # For this simple demo, we'll do Send -> Receive lock-step.
            msg = input("Alice: ")
            if msg.lower() == 'exit': break
            
            encrypted_msg = encrypt_message(session_key, msg)
            s.sendall(encrypted_msg)
            
            # Wait for Bob
            encrypted_response = s.recv(4096)
            if not encrypted_response: break
            
            try:
                decrypted = decrypt_message(session_key, encrypted_response)
                print(f"\nBob: {decrypted.decode()}")
            except Exception as e:
                print(f"\n[-] Decryption Failed: {e}")
                break

if __name__ == "__main__":
    start_client()
