
# ==================================================
# DES SECURITY LAB
# Educational Brute Force Attack Engine
# ==================================================

import time

from des_engine import encrypt_block


# ==================================================
# 1. CONVERT REDUCED KEY TO DES KEY
# ==================================================

def candidate_to_des_key(candidate, key_bits):
    """
    Convert a reduced key candidate into a 64-bit DES key.

    The candidate bits are placed into the 56 effective
    DES key positions, with odd parity added to each byte.
    """

    if key_bits < 1 or key_bits > 56:
        raise ValueError("Key size must be between 1 and 56 bits.")

    if candidate < 0 or candidate >= (1 << key_bits):
        raise ValueError("Candidate does not fit the selected key size.")

    candidate_bits = format(candidate, f"0{key_bits}b")
    effective_bits = candidate_bits.ljust(56, "0")

    key_bytes = bytearray()

    for i in range(8):
        seven_bits = effective_bits[i * 7:(i + 1) * 7]
        value = int(seven_bits, 2) << 1

        # Set the final bit to produce odd parity.
        if value.bit_count() % 2 == 0:
            value |= 1

        key_bytes.append(value)

    return int.from_bytes(key_bytes, "big")


# ==================================================
# 2. BRUTE FORCE ATTACK
# ==================================================

def brute_force_attack(plaintext, target_ciphertext_hex, key_bits):
    """
    Educational brute force attack against a reduced DES keyspace.

    Requirements:
    - Plaintext must be exactly 8 bytes.
    - Target ciphertext must be exactly 16 hexadecimal characters.
    - Key size must be between 1 and 24 bits for this lab.
    """

    if not isinstance(plaintext, str):
        raise ValueError("Plaintext must be a string.")

    plaintext_bytes = plaintext.encode("utf-8")

    if len(plaintext_bytes) != 8:
        raise ValueError("Plaintext must be exactly 8 UTF-8 bytes.")

    if not isinstance(target_ciphertext_hex, str):
        raise ValueError("Ciphertext must be a hexadecimal string.")

    if len(target_ciphertext_hex) != 16:
        raise ValueError("Ciphertext must contain exactly 16 hexadecimal characters.")

    try:
        target_ciphertext = int(target_ciphertext_hex, 16)
    except ValueError:
        raise ValueError("Ciphertext contains invalid hexadecimal characters.")

    if key_bits < 1 or key_bits > 24:
        raise ValueError("Educational key size must be between 1 and 24 bits.")

    plaintext_block = int.from_bytes(plaintext_bytes, "big")

    total_keys = 1 << key_bits
    attempts = 0

    start_time = time.perf_counter()

    for candidate in range(total_keys):

        attempts += 1

        candidate_key = candidate_to_des_key(
            candidate,
            key_bits
        )

        encrypted_block = encrypt_block(
            plaintext_block,
            candidate_key
        )

        if encrypted_block == target_ciphertext:

            elapsed_time = time.perf_counter() - start_time

            return {
                "success": True,
                "found": True,
                "key": f"{candidate_key:016X}",
                "candidate": candidate,
                "key_bits": key_bits,
                "attempts": attempts,
                "total_keys": total_keys,
                "elapsed_seconds": round(elapsed_time, 6)
            }

    elapsed_time = time.perf_counter() - start_time

    return {
        "success": True,
        "found": False,
        "key": None,
        "candidate": None,
        "key_bits": key_bits,
        "attempts": attempts,
        "total_keys": total_keys,
        "elapsed_seconds": round(elapsed_time, 6)
    }


# ==================================================
# 3. DEMONSTRATION TEST
# ==================================================

if __name__ == "__main__":

    print("=" * 55)
    print("DES SECURITY LAB - BRUTE FORCE VERIFICATION")
    print("=" * 55)

    test_plaintext = "DES TEST"

    test_key_bits = 8
    secret_candidate = 42

    secret_key = candidate_to_des_key(
        secret_candidate,
        test_key_bits
    )

    plaintext_block = int.from_bytes(
        test_plaintext.encode("utf-8"),
        "big"
    )

    target_ciphertext = encrypt_block(
        plaintext_block,
        secret_key
    )

    target_hex = f"{target_ciphertext:016X}"

    print("\n[TEST INFORMATION]")
    print("Plaintext:", test_plaintext)
    print("Key size:", test_key_bits, "bits")
    print("Target ciphertext:", target_hex)

    print("\n[STARTING BRUTE FORCE ATTACK]")

    result = brute_force_attack(
        test_plaintext,
        target_hex,
        test_key_bits
    )

    print("\n[ATTACK RESULTS]")
    print("Success:", result["success"])
    print("Key found:", result["found"])
    print("Recovered key:", result["key"])
    print("Candidate:", result["candidate"])
    print("Attempts:", result["attempts"])
    print("Total possible keys:", result["total_keys"])
    print("Elapsed time:", result["elapsed_seconds"], "seconds")

    print("\n" + "=" * 55)

    if result["found"] and result["candidate"] == secret_candidate:
        print("BRUTE FORCE TEST PASSED!")
    else:
        print("BRUTE FORCE TEST FAILED!")
