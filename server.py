import socket
import oqs
import os
import json
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

def start_server():
    print(f"--- 1. BOB (SERVER) STARTING UP ---")
    
    # --- STEP A: GENERATE KEYS ---
    print("[*] Generating Crypto Assets...")
    
    # 1. Quantum Identity (Sig)
    sid_sig = oqs.Signature(SIG_ALG)
    pub_sig = sid_sig.generate_keypair()
    
    # 2. Quantum Padlock (KEM)
    sid_kem = oqs.KeyEncapsulation(KEM_ALG)
    pub_kem = sid_kem.generate_keypair()
    
    # 3. Classical Keypair (ECDHE)
    priv_ec = ec.generate_private_key(ec.SECP256R1())
    pub_ec = priv_ec.public_key()
    pub_ec_bytes = pub_ec.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # --- STEP B: SIGN EVERYTHING ---
    # Bob signs (Quantum_Pub + Classical_Pub) to prove he owns BOTH.
    print("[*] Signing Public Keys...")
    data_to_sign = pub_kem + pub_ec_bytes
    signature = sid_sig.sign(data_to_sign)
    
    # --- STEP C: LISTEN FOR ALICE ---
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print(f"[*] Listening on {HOST}:{PORT}...")
        
        conn, addr = s.accept()
        with conn:
            print(f"[+] Connected by {addr}")
            
            # --- STEP D: SEND HANDSHAKE BUNDLE ---
            print("[*] Sending Handshake Bundle...")
            # We send length-prefixed data or just use a delimiter. 
            # For simplicity in this demo, we'll use a JSON wrapper encoded to bytes.
            bundle = {
                "pub_sig": pub_sig.hex(),
                "pub_kem": pub_kem.hex(),
                "pub_ec": pub_ec_bytes.hex(),
                "signature": signature.hex()
            }
            conn.sendall(json.dumps(bundle).encode() + b"\n")
            
            # --- STEP E: RECEIVE CLIENT RESPONSE ---
            # Alice sends back: [KEM_Ciphertext, Alice_EC_Pub]
            print("[*] Waiting for Alice's Encapsulation...")
            data = conn.recv(16384) # Should be enough for handshake
            response = json.loads(data.decode())
            
            kem_ciphertext = bytes.fromhex(response['kem_ciphertext'])
            alice_pub_ec_bytes = bytes.fromhex(response['pub_ec'])
            
            # --- STEP F: DERIVE SECRETS ---
            print("[*] Decapsulating & Deriving Hybrid Key...")
            
            # 1. Quantum Shared Secret
            shared_secret_quantum = sid_kem.decap_secret(kem_ciphertext)
            
            # 2. Classical Shared Secret
            alice_pub_ec = serialization.load_pem_public_key(alice_pub_ec_bytes)
            shared_secret_classical = priv_ec.exchange(ec.ECDH(), alice_pub_ec)
            
            # 3. Hybrid Key
            session_key = derive_hybrid_key(shared_secret_quantum, shared_secret_classical)
            print("[+] SECURE CONNECTION ESTABLISHED!")
            print(f"    Hybrid Key (First 16 bytes): {session_key.hex()[:16]}...")
            
            # --- STEP G: CHAT LOOP ---
            print("\n--- CHAT SESSION STARTED (Type 'exit' to quit) ---")
            while True:
                # Receive first
                encrypted_data = conn.recv(4096)
                if not encrypted_data: break
                
                try:
                    decrypted = decrypt_message(session_key, encrypted_data)
                    print(f"\nAlice: {decrypted.decode()}")
                except Exception as e:
                    print(f"\n[-] Decryption Failed: {e}")
                    break
                
                # Reply
                msg = input("Bob: ")
                if msg.lower() == 'exit': break
                
                encrypted_response = encrypt_message(session_key, msg)
                conn.sendall(encrypted_response)

if __name__ == "__main__":
    start_server()
