
# ==========================================================
# DES SECURITY LAB
# Weak and Semi-Weak Keys Analysis
# Educational Security Experiment
# ==========================================================

from des_engine import encrypt_block


# ==========================================================
# 1. STANDARD DES WEAK KEYS (4)
# ==========================================================

WEAK_KEYS = [
    "0101010101010101",
    "FEFEFEFEFEFEFEFE",
    "E0E0E0E0F1F1F1F1",
    "1F1F1F1F0E0E0E0E",
]


# ==========================================================
# 2. STANDARD DES SEMI-WEAK KEY PAIRS (6)
# ==========================================================

SEMI_WEAK_PAIRS = [
    (
        "01FE01FE01FE01FE",
        "FE01FE01FE01FE01",
    ),
    (
        "1FE01FE00EF10EF1",
        "E01FE01FF10EF10E",
    ),
    (
        "01E001E001F101F1",
        "E001E001F101F101",
    ),
    (
        "1FFE1FFE0EFE0EFE",
        "FE1FFE1FFE0EFE0E",
    ),
    (
        "011F011F010E010E",
        "1F011F010E010E01",
    ),
    (
        "E0FEE0FEF1FEF1FE",
        "FEE0FEE0FEF1FEF1",
    ),
]


# ==========================================================
# 3. TEST DATA
# ==========================================================

TEST_BLOCK = 0x0123456789ABCDEF


# ==========================================================
# 4. WEAK KEY VERIFICATION
# ==========================================================

def test_weak_key(key_hex):
    """
    A DES weak key encrypts a block twice
    to recover the original plaintext.
    E(K, E(K, P)) = P
    """

    key = int(key_hex, 16)

    first_encryption = encrypt_block(TEST_BLOCK, key)

    second_encryption = encrypt_block(first_encryption, key)

    return {
        "key": key_hex,
        "passed": second_encryption == TEST_BLOCK,
        "first_encryption": f"{first_encryption:016X}",
        "recovered_block": f"{second_encryption:016X}",
    }


# ==========================================================
# 5. SEMI-WEAK KEY PAIR VERIFICATION
# ==========================================================

def test_semi_weak_pair(key1_hex, key2_hex):
    """
    Semi-weak keys work in pairs.

    Encrypting with one key and then
    encrypting with its paired key
    recovers the original plaintext.

    E(K1, E(K2, P)) = P
    """

    key1 = int(key1_hex, 16)
    key2 = int(key2_hex, 16)

    first_encryption = encrypt_block(TEST_BLOCK, key2)

    recovered_block = encrypt_block(first_encryption, key1)

    return {
        "key1": key1_hex,
        "key2": key2_hex,
        "passed": recovered_block == TEST_BLOCK,
        "recovered_block": f"{recovered_block:016X}",
    }


# ==========================================================
# 6. COMPLETE SECURITY ANALYSIS
# ==========================================================

def run_weak_key_analysis():

    print("=" * 65)
    print("DES SECURITY LAB - WEAK KEY ANALYSIS")
    print("=" * 65)

    print(f"\nTest plaintext: {TEST_BLOCK:016X}")

    # ------------------------------------------------------
    # Weak Keys
    # ------------------------------------------------------

    print("\n[1] WEAK KEYS TEST")
    print("-" * 65)

    weak_results = []

    for index, key in enumerate(WEAK_KEYS, start=1):

        result = test_weak_key(key)

        weak_results.append(result)

        status = "PASS" if result["passed"] else "FAIL"

        print(f"\nWeak Key #{index}")
        print(f"Key:              {result['key']}")
        print(f"First Encryption: {result['first_encryption']}")
        print(f"Recovered Block:  {result['recovered_block']}")
        print(f"Result:           {status}")

    # ------------------------------------------------------
    # Semi-Weak Keys
    # ------------------------------------------------------

    print("\n\n[2] SEMI-WEAK KEY PAIRS TEST")
    print("-" * 65)

    semi_results = []

    for index, (key1, key2) in enumerate(
        SEMI_WEAK_PAIRS, start=1
    ):

        result = test_semi_weak_pair(key1, key2)

        semi_results.append(result)

        status = "PASS" if result["passed"] else "FAIL"

        print(f"\nSemi-Weak Pair #{index}")
        print(f"Key 1:            {result['key1']}")
        print(f"Key 2:            {result['key2']}")
        print(f"Recovered Block:  {result['recovered_block']}")
        print(f"Result:           {status}")

    # ------------------------------------------------------
    # Final Summary
    # ------------------------------------------------------

    weak_passed = sum(r["passed"] for r in weak_results)

    semi_passed = sum(r["passed"] for r in semi_results)

    print("\n\n[3] FINAL ANALYSIS SUMMARY")
    print("=" * 65)

    print(f"Weak Keys Tested:       {len(weak_results)}")
    print(f"Weak Keys Passed:       {weak_passed}")

    print(f"Semi-Weak Pairs Tested: {len(semi_results)}")
    print(f"Semi-Weak Pairs Passed: {semi_passed}")

    all_passed = (
        weak_passed == len(WEAK_KEYS)
        and semi_passed == len(SEMI_WEAK_PAIRS)
    )

    print("\nOverall Result:", "ALL TESTS PASSED" if all_passed else "SOME TESTS FAILED")

    print("=" * 65)

    return all_passed


# ==========================================================
# 7. PROGRAM ENTRY POINT
# ==========================================================

if __name__ == "__main__":

    success = run_weak_key_analysis()

    if not success:
        raise SystemExit("Weak Key Analysis failed.")
