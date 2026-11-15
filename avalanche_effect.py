
# ==================================================
# DES SECURITY LAB
# AVALANCHE EFFECT ANALYSIS
# Measure the impact of changing one input bit
# ==================================================

from des_engine import encrypt_block


# Standard DES test values
TEST_PLAINTEXT = 0x0123456789ABCDEF
TEST_KEY = 0x133457799BBCDFF1

BLOCK_SIZE = 64


def count_different_bits(value1, value2):
    """Count the number of different bits between two values."""
    return (value1 ^ value2).bit_count()


def calculate_percentage(changed_bits, total_bits):
    """Calculate the percentage of changed bits."""
    return (changed_bits / total_bits) * 100


def run_avalanche_analysis():

    # ==============================================
    # 1. ORIGINAL ENCRYPTION
    # ==============================================

    original_ciphertext = encrypt_block(
        TEST_PLAINTEXT,
        TEST_KEY
    )

    # ==============================================
    # 2. CHANGE ONE PLAINTEXT BIT
    # Keep the key unchanged
    # ==============================================

    modified_plaintext = TEST_PLAINTEXT ^ (1 << 63)

    plaintext_ciphertext = encrypt_block(
        modified_plaintext,
        TEST_KEY
    )

    plaintext_changed_bits = count_different_bits(
        original_ciphertext,
        plaintext_ciphertext
    )

    plaintext_percentage = calculate_percentage(
        plaintext_changed_bits,
        BLOCK_SIZE
    )

    # ==============================================
    # 3. CHANGE ONE KEY BIT
    # Keep the plaintext unchanged
    # ==============================================

    # Bit position 1 is an effective DES key bit,
    # not a parity bit.
    modified_key = TEST_KEY ^ (1 << 62)

    key_ciphertext = encrypt_block(
        TEST_PLAINTEXT,
        modified_key
    )

    key_changed_bits = count_different_bits(
        original_ciphertext,
        key_ciphertext
    )

    key_percentage = calculate_percentage(
        key_changed_bits,
        BLOCK_SIZE
    )

    # ==============================================
    # 4. BUILD RESULTS
    # ==============================================

    results = {
        "success": True,

        "block_size": BLOCK_SIZE,

        "original_plaintext": f"{TEST_PLAINTEXT:016X}",
        "original_key": f"{TEST_KEY:016X}",
        "original_ciphertext": f"{original_ciphertext:016X}",

        "plaintext_test": {
            "modified_plaintext": f"{modified_plaintext:016X}",
            "modified_ciphertext": f"{plaintext_ciphertext:016X}",
            "changed_bits": plaintext_changed_bits,
            "percentage": round(plaintext_percentage, 2)
        },

        "key_test": {
            "modified_key": f"{modified_key:016X}",
            "modified_ciphertext": f"{key_ciphertext:016X}",
            "changed_bits": key_changed_bits,
            "percentage": round(key_percentage, 2)
        }
    }

    return results


# ==============================================
# 5. RUN STANDALONE TEST
# ==============================================

if __name__ == "__main__":

    print("=" * 60)
    print("DES SECURITY LAB - AVALANCHE EFFECT ANALYSIS")
    print("=" * 60)

    results = run_avalanche_analysis()

    print("\n[ORIGINAL ENCRYPTION]")
    print("Plaintext:  ", results["original_plaintext"])
    print("Key:        ", results["original_key"])
    print("Ciphertext: ", results["original_ciphertext"])

    print("\n[TEST 1] CHANGE ONE PLAINTEXT BIT")
    print("-" * 60)

    test1 = results["plaintext_test"]

    print("Modified Plaintext: ", test1["modified_plaintext"])
    print("New Ciphertext:     ", test1["modified_ciphertext"])
    print("Changed Bits:       ", test1["changed_bits"], "/ 64")
    print("Change Percentage: ", test1["percentage"], "%")

    print("\n[TEST 2] CHANGE ONE KEY BIT")
    print("-" * 60)

    test2 = results["key_test"]

    print("Modified Key:       ", test2["modified_key"])
    print("New Ciphertext:     ", test2["modified_ciphertext"])
    print("Changed Bits:       ", test2["changed_bits"], "/ 64")
    print("Change Percentage: ", test2["percentage"], "%")

    print("\n" + "=" * 60)
    print("AVALANCHE ANALYSIS COMPLETED")
    print("=" * 60)
