import oqs
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def authenticated_hybrid_key_exchange():
    kem_name = "ML-KEM-512"
    sig_name = "ML-DSA-44"
    
    print(f"\n--- INITIATING AUTHENTICATED HYBRID HANDSHAKE ({kem_name} + {sig_name}) ---")
    
    # 1. BOB'S WORKSHOP (The Server)
    # Bob needs both a KEM context (for encryption) and a Signature context (for identity)
    with oqs.KeyEncapsulation(kem_name) as bob_kem:
        with oqs.Signature(sig_name) as bob_sig:
            print("\n1. BOB: Generating Identity and Padlock...")
            
            # Identity: Bob generates his long-term Signing Keypair
            public_key_sig = bob_sig.generate_keypair()
            
            # Ephemeral: Bob generates his session-specific KEM Keypair
            public_key_kem = bob_kem.generate_keypair()
            
            # AUTHENTICATION STEP: Bob signs his KEM Public Key
            # This binds the "Padlock" to his "Identity"
            print("   [Bob signs his Quantum Padlock with his Digital Signature]")
            signature = bob_sig.sign(public_key_kem)
            
            # --- NETWORK TRANSMISSION (Simulated) ---
            # Bob sends [public_key_kem, public_key_sig, signature] to Alice
            
            # 2. ALICE'S WORKSHOP (The Client)
            with oqs.KeyEncapsulation(kem_name) as alice_kem:
                with oqs.Signature(sig_name) as alice_sig:
                    print("\n2. ALICE: Verifying Bob's Identity...")
                    
                    # VERIFICATION STEP: Alice checks the signature
                    # She uses Bob's Signing Public Key to verify the KEM Public Key was signed by him
                    is_valid = alice_sig.verify(public_key_kem, signature, public_key_sig)
                    
                    if is_valid:
                        print("   [+] SIGNATURE VALIDATED! This padlock is authentically Bob's.")
                    else:
                        print("   [-] SECURITY ALERT! Signature Invalid. Aborting connection.")
                        return

                    print("3. ALICE: Encapsulating the Secret...")
                    ciphertext, shared_secret_alice = alice_kem.encap_secret(public_key_kem)
            
            # 3. BOB OPENS THE BOX
            print("\n4. BOB: Decapsulating the Box...")
            shared_secret_bob = bob_kem.decap_secret(ciphertext)
            
            # --- SHARED SECRET VERIFICATION ---
            if shared_secret_alice == shared_secret_bob:
                print("   [+] SUCCESS! Quantum secrets match perfectly.")
            else:
                print("   [-] FAILED! Keys do not match.")
                return

            # ==========================================
            # 4. THE HYBRIDIZATION (Belt and Suspenders)
            # ==========================================
            print("\n5. HYBRIDIZATION: Deriving Final Session Key...")
            
            # Simulate a classical ECDHE secret
            classical_shared_secret = os.urandom(32) 
            
            # Concatenate (Mix) Quantum + Classical secrets
            combined_material = classical_shared_secret + shared_secret_bob
            
            # Key Derivation Function (HKDF)
            final_encryption_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"pqc-authenticated-v2",
            ).derive(combined_material)
            
            print(f"\n--- HANDSHAKE COMPLETE ---")
            print(f"Final Hybrid AES-256 Key: {final_encryption_key.hex()[:32]}...")

if __name__ == "__main__":
    authenticated_hybrid_key_exchange()