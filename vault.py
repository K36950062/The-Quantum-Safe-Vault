import oqs
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def hybrid_key_exchange():
    kem_name = "ML-KEM-512"
    print(f"\n--- INITIATING HYBRID HANDSHAKE ({kem_name}) ---")
    
    # 1. BOB'S WORKSHOP
    # We keep Bob's environment open so his Private Key stays safe in RAM
    with oqs.KeyEncapsulation(kem_name) as bob:
        print("\n1. BOB: Generating Quantum Keypair...")
        public_key_bob = bob.generate_keypair()
        
        # 2. ALICE'S WORKSHOP
        with oqs.KeyEncapsulation(kem_name) as alice:
            print("2. ALICE: Encapsulating the Secret...")
            ciphertext, shared_secret_alice = alice.encap_secret(public_key_bob)
            
        # 3. BOB OPENS THE BOX
        print("3. BOB: Decapsulating the Box...")
        shared_secret_bob = bob.decap_secret(ciphertext)
        
        # --- VERIFICATION ---
        if shared_secret_alice == shared_secret_bob:
            print("\n   [+] SUCCESS! Quantum secrets match perfectly.")
        else:
            print("\n   [-] FAILED! Keys do not match. Eve might be listening.")
            return

        # ==========================================
        # 4. THE HYBRIDIZATION (Belt and Suspenders)
        # ==========================================
        print("\n4. HYBRIDIZATION: Mixing Quantum and Classical Math...")
        
        # In a real network, Alice and Bob would also do a standard ECDHE (Classical) 
        # handshake here. For this script, we simulate the resulting classical key.
        classical_shared_secret = os.urandom(32) 
        
        # We concatenate (mix) the Classical and Quantum secrets together
        combined_material = classical_shared_secret + shared_secret_bob
        
        # We use a Key Derivation Function (HKDF) to hash the mixed materials 
        # down into one perfectly uniform, unbreakable 32-byte key.
        final_encryption_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"pqc-migration-v1",
        ).derive(combined_material)
        
        print(f"\n--- PHASE 1 COMPLETE ---")
        print(f"Final Hybrid AES-256 Key: {final_encryption_key.hex()[:32]}...")

if __name__ == "__main__":
    hybrid_key_exchange()