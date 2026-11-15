
# ==================================================
# DES SECURITY LAB
# DES Encryption Engine
# Core Implementation: Complete DES Algorithm
# ==================================================


# ==================================================
# 1. BASIC BIT OPERATIONS
# ==================================================

def int_to_bits(value, width):
    """Convert an integer into a fixed-width bit list."""
    if value < 0 or value >= (1 << width):
        raise ValueError("Value does not fit the requested bit width")

    return [
        (value >> (width - 1 - i)) & 1
        for i in range(width)
    ]


def bits_to_int(bits):
    """Convert a bit list into an integer."""
    value = 0

    for bit in bits:
        value = (value << 1) | bit

    return value


def permute(bits, table):
    """Apply a permutation table to a bit list."""
    return [bits[position - 1] for position in table]


def xor_bits(left, right):
    """Perform XOR between two equal-length bit lists."""
    if len(left) != len(right):
        raise ValueError("Bit lists must have equal length")

    return [a ^ b for a, b in zip(left, right)]


# ==================================================
# 2. DES PERMUTATION TABLES
# ==================================================

IP_TABLE = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

FP_TABLE = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

PC1_TABLE = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21,
    13, 5, 28, 20, 12, 4
]

PC2_TABLE = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]

SHIFT_SCHEDULE = [
    1, 1, 2, 2, 2, 2, 2, 2,
    1, 2, 2, 2, 2, 2, 2, 1
]

E_TABLE = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

P_TABLE = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25
]


# ==================================================
# 3. DES S-BOXES
# ==================================================

S_BOXES = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]


# ==================================================
# 4. DES PERMUTATION FUNCTIONS
# ==================================================

def initial_permutation(block):
    """Apply the DES Initial Permutation."""
    if len(block) != 64:
        raise ValueError("DES block must contain exactly 64 bits")

    return permute(block, IP_TABLE)


def final_permutation(block):
    """Apply the DES Final Permutation."""
    if len(block) != 64:
        raise ValueError("DES block must contain exactly 64 bits")

    return permute(block, FP_TABLE)


def expansion_permutation(right_half):
    """Expand a 32-bit right half into 48 bits."""
    if len(right_half) != 32:
        raise ValueError("Right half must contain exactly 32 bits")

    return permute(right_half, E_TABLE)


def p_permutation(bits):
    """Apply the DES P Permutation."""
    if len(bits) != 32:
        raise ValueError("P permutation input must contain exactly 32 bits")

    return permute(bits, P_TABLE)


# ==================================================
# 5. DES S-BOX SUBSTITUTION
# ==================================================

def sbox_substitution(input_bits):
    """Convert 48 input bits into 32 output bits."""

    if len(input_bits) != 48:
        raise ValueError("S-Box input must contain exactly 48 bits")

    if any(bit not in (0, 1) for bit in input_bits):
        raise ValueError("Input must contain only binary values")

    output_bits = []

    for i in range(8):
        block = input_bits[i * 6:(i + 1) * 6]

        row = bits_to_int([block[0], block[5]])
        column = bits_to_int(block[1:5])

        sbox_value = S_BOXES[i][row][column]

        output_bits.extend(int_to_bits(sbox_value, 4))

    return output_bits


# ==================================================
# 6. DES KEY SCHEDULE
# ==================================================

def generate_round_keys(key):
    """Generate the 16 DES round keys."""

    if not isinstance(key, int) or isinstance(key, bool):
        raise TypeError("DES key must be an integer")

    if not 0 <= key < (1 << 64):
        raise ValueError("DES key must be a 64-bit integer")

    key_bits = int_to_bits(key, 64)

    permuted_key = permute(key_bits, PC1_TABLE)

    C = permuted_key[:28]
    D = permuted_key[28:]

    round_keys = []

    for shift in SHIFT_SCHEDULE:
        C = C[shift:] + C[:shift]
        D = D[shift:] + D[:shift]

        combined = C + D

        round_key = permute(combined, PC2_TABLE)

        round_keys.append(round_key)

    return round_keys


# ==================================================
# 7. FEISTEL FUNCTION
# ==================================================

def feistel_function(right_half, round_key):
    """
    DES F Function:
    Expansion -> XOR -> S-Box -> P Permutation
    """

    if len(right_half) != 32:
        raise ValueError("Right half must contain exactly 32 bits")

    if len(round_key) != 48:
        raise ValueError("Round key must contain exactly 48 bits")

    expanded = expansion_permutation(right_half)

    mixed = xor_bits(expanded, round_key)

    substituted = sbox_substitution(mixed)

    result = p_permutation(substituted)

    return result


# ==================================================
# 8. DES ENCRYPTION
# ==================================================

def encrypt_block(block, key, return_trace=False):
    """
    Encrypt one 64-bit block using DES.

    Returns the encrypted 64-bit integer.
    If return_trace=True, also returns round details.
    """

    if not isinstance(block, int) or isinstance(block, bool):
        raise TypeError("Plaintext block must be an integer")

    if not 0 <= block < (1 << 64):
        raise ValueError("Plaintext block must be 64 bits")

    round_keys = generate_round_keys(key)

    block_bits = int_to_bits(block, 64)
    permuted_block = initial_permutation(block_bits)

    L = permuted_block[:32]
    R = permuted_block[32:]

    trace = []

    for round_number in range(16):

        old_L = L
        old_R = R

        current_round_key = round_keys[round_number]

        f_result = feistel_function(
            old_R,
            current_round_key
        )

        L = old_R
        R = xor_bits(old_L, f_result)

        trace.append({
            "round": round_number + 1,
            "left": bits_to_int(L),
            "right": bits_to_int(R),
            "round_key": bits_to_int(current_round_key)
        })

    combined = R + L

    encrypted_bits = final_permutation(combined)

    ciphertext = bits_to_int(encrypted_bits)

    if return_trace:
        return ciphertext, trace

    return ciphertext


# ==================================================
# 9. DES DECRYPTION
# ==================================================

def decrypt_block(block, key, return_trace=False):
    """
    Decrypt one 64-bit block using DES.
    Round keys are used in reverse order.
    """

    if not isinstance(block, int) or isinstance(block, bool):
        raise TypeError("Ciphertext block must be an integer")

    if not 0 <= block < (1 << 64):
        raise ValueError("Ciphertext block must be 64 bits")

    round_keys = generate_round_keys(key)

    round_keys.reverse()

    block_bits = int_to_bits(block, 64)
    permuted_block = initial_permutation(block_bits)

    L = permuted_block[:32]
    R = permuted_block[32:]

    trace = []

    for round_number in range(16):

        old_L = L
        old_R = R

        current_round_key = round_keys[round_number]

        f_result = feistel_function(
            old_R,
            current_round_key
        )

        L = old_R
        R = xor_bits(old_L, f_result)

        trace.append({
            "round": round_number + 1,
            "left": bits_to_int(L),
            "right": bits_to_int(R),
            "round_key": bits_to_int(current_round_key)
        })

    combined = R + L

    decrypted_bits = final_permutation(combined)

    plaintext = bits_to_int(decrypted_bits)

    if return_trace:
        return plaintext, trace

    return plaintext


# ==================================================
# 10. TEXT ENCRYPTION LAYER
# ==================================================

BLOCK_SIZE = 8


def validate_key_hex(key_hex):
    """Validate a DES key represented as 16 hexadecimal characters."""

    if not isinstance(key_hex, str):
        raise TypeError("Key must be a hexadecimal string")

    if len(key_hex) != 16:
        raise ValueError(
            "DES key must contain exactly 16 hexadecimal characters"
        )

    try:
        return int(key_hex, 16)
    except ValueError:
        raise ValueError("Key must contain only hexadecimal characters")


def add_padding(data):
    """Apply PKCS#5-compatible padding for an 8-byte DES block."""

    padding_length = BLOCK_SIZE - (len(data) % BLOCK_SIZE)

    return data + bytes([padding_length] * padding_length)


def remove_padding(data):
    """Remove and validate padding after decryption."""

    if not data or len(data) % BLOCK_SIZE != 0:
        raise ValueError("Invalid padded data length")

    padding_length = data[-1]

    if not 1 <= padding_length <= BLOCK_SIZE:
        raise ValueError("Invalid padding")

    if data[-padding_length:] != bytes([padding_length] * padding_length):
        raise ValueError("Invalid padding")

    return data[:-padding_length]


def encrypt_text(plaintext, key_hex):
    """Encrypt UTF-8 text using DES in ECB mode."""

    if not isinstance(plaintext, str):
        raise TypeError("Plaintext must be a string")

    key = validate_key_hex(key_hex)

    plaintext_bytes = plaintext.encode("utf-8")

    padded_data = add_padding(plaintext_bytes)

    encrypted_blocks = []

    for i in range(0, len(padded_data), BLOCK_SIZE):

        block_bytes = padded_data[i:i + BLOCK_SIZE]

        block_int = int.from_bytes(
            block_bytes,
            byteorder="big"
        )

        encrypted_int = encrypt_block(block_int, key)

        encrypted_bytes = encrypted_int.to_bytes(
            BLOCK_SIZE,
            byteorder="big"
        )

        encrypted_blocks.append(encrypted_bytes)

    ciphertext = b"".join(encrypted_blocks)

    return ciphertext.hex().upper()


def decrypt_text(ciphertext_hex, key_hex):
    """Decrypt DES ECB ciphertext and return UTF-8 text."""

    if not isinstance(ciphertext_hex, str):
        raise TypeError("Ciphertext must be a hexadecimal string")

    key = validate_key_hex(key_hex)

    if not ciphertext_hex:
        raise ValueError("Ciphertext cannot be empty")

    if len(ciphertext_hex) % 16 != 0:
        raise ValueError(
            "Ciphertext length must be a multiple of 16 hex characters"
        )

    try:
        ciphertext = bytes.fromhex(ciphertext_hex)
    except ValueError:
        raise ValueError(
            "Ciphertext must contain only hexadecimal characters"
        )

    decrypted_blocks = []

    for i in range(0, len(ciphertext), BLOCK_SIZE):

        block_bytes = ciphertext[i:i + BLOCK_SIZE]

        block_int = int.from_bytes(
            block_bytes,
            byteorder="big"
        )

        decrypted_int = decrypt_block(block_int, key)

        decrypted_bytes = decrypted_int.to_bytes(
            BLOCK_SIZE,
            byteorder="big"
        )

        decrypted_blocks.append(decrypted_bytes)

    padded_plaintext = b"".join(decrypted_blocks)

    plaintext_bytes = remove_padding(padded_plaintext)

    try:
        return plaintext_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Decrypted data is not valid UTF-8 text")


# ==================================================
# 11. VERIFICATION AND TESTS
# ==================================================

if __name__ == "__main__":

    print("=" * 50)
    print("DES SECURITY LAB - VERIFICATION")
    print("=" * 50)

    test_key = 0x133457799BBCDFF1
    round_keys = generate_round_keys(test_key)

    print("\n[TEST 1] DES Key Schedule")
    print("-------------------------")
    print("Number of round keys:", len(round_keys))
    print("Bits per round key:", len(round_keys[0]))
    print("First round key:", hex(bits_to_int(round_keys[0])))
    print("Last round key:", hex(bits_to_int(round_keys[-1])))

    # Test Initial and Final Permutation
    test_value = 0x123456789ABCDEF0

    bits = int_to_bits(test_value, 64)

    after_ip = initial_permutation(bits)
    after_fp = final_permutation(after_ip)

    print("\n[TEST 2] Initial and Final Permutation")
    print("--------------------------------------")
    print("Original block:", hex(test_value))
    print("After IP:", hex(bits_to_int(after_ip)))
    print("After FP:", hex(bits_to_int(after_fp)))
    print("Recovered original:", bits_to_int(after_fp) == test_value)

    # Test Expansion
    test_right = 0xF0AAF0AA

    right_bits = int_to_bits(test_right, 32)
    expanded_bits = expansion_permutation(right_bits)

    print("\n[TEST 3] Expansion Function")
    print("---------------------------")
    print("Original R:", hex(test_right))
    print("Expanded R:", hex(bits_to_int(expanded_bits)))
    print("Expanded length:", len(expanded_bits))
    print("Expansion successful:", len(expanded_bits) == 48)

    # Test S-Boxes
    test_sbox_input = [0] * 48
    sbox_output = sbox_substitution(test_sbox_input)

    print("\n[TEST 4] S-Box Substitution")
    print("--------------------------")
    print("Input length:", len(test_sbox_input))
    print("Output:", hex(bits_to_int(sbox_output)))
    print("Output length:", len(sbox_output))
    print("S-Box successful:", len(sbox_output) == 32)

    # Test P Permutation
    p_test_input = int_to_bits(0xEFA72C4D, 32)
    p_test_output = p_permutation(p_test_input)

    print("\n[TEST 5] P Permutation")
    print("---------------------")
    print("Input:", hex(bits_to_int(p_test_input)))
    print("Output:", hex(bits_to_int(p_test_output)))
    print("Output length:", len(p_test_output))
    print("P Permutation successful:", len(p_test_output) == 32)

    # Test Feistel Function
    feistel_test_right = int_to_bits(0xF0AAF0AA, 32)
    feistel_test_key = round_keys[0]

    feistel_output = feistel_function(
        feistel_test_right,
        feistel_test_key
    )

    print("\n[TEST 6] Feistel Function")
    print("-------------------------")
    print("Input R length:", len(feistel_test_right))
    print("Round key length:", len(feistel_test_key))
    print("Output:", hex(bits_to_int(feistel_output)))
    print("Output length:", len(feistel_output))
    print("Feistel successful:", len(feistel_output) == 32)

    # Standard DES test vector
    plaintext = 0x0123456789ABCDEF
    expected_ciphertext = 0x85E813540F0AB405

    ciphertext, encryption_trace = encrypt_block(
        plaintext,
        test_key,
        return_trace=True
    )

    print("\n[TEST 7] DES Encryption")
    print("-----------------------")
    print("Plaintext:", hex(plaintext))
    print("Key:", hex(test_key))
    print("Expected ciphertext:", hex(expected_ciphertext))
    print("Actual ciphertext:", hex(ciphertext))
    print("Encryption successful:", ciphertext == expected_ciphertext)

    print("\nEncryption Round Details")
    print("------------------------")

    for item in encryption_trace:
        print(
            f"Round {item['round']:02d} | "
            f"L = {item['left']:08X} | "
            f"R = {item['right']:08X} | "
            f"Key = {item['round_key']:012X}"
        )

    # Test Decryption
    decrypted_text, decryption_trace = decrypt_block(
        ciphertext,
        test_key,
        return_trace=True
    )

    print("\n[TEST 8] DES Decryption")
    print("-----------------------")
    print("Ciphertext:", hex(ciphertext))
    print("Decrypted plaintext:", hex(decrypted_text))
    print("Original plaintext:", hex(plaintext))
    print("Decryption successful:", decrypted_text == plaintext)

    print("\nDecryption Round Details")
    print("------------------------")

    for item in decryption_trace:
        print(
            f"Round {item['round']:02d} | "
            f"L = {item['left']:08X} | "
            f"R = {item['right']:08X} | "
            f"Key = {item['round_key']:012X}"
        )

    # Final Summary
    all_tests_passed = (
        len(round_keys) == 16
        and bits_to_int(after_fp) == test_value
        and len(expanded_bits) == 48
        and len(sbox_output) == 32
        and len(p_test_output) == 32
        and len(feistel_output) == 32
        and ciphertext == expected_ciphertext
        and decrypted_text == plaintext
        and len(encryption_trace) == 16
        and len(decryption_trace) == 16
        and all("round_key" in item for item in encryption_trace)
        and all("round_key" in item for item in decryption_trace)
    )

    print("\n" + "=" * 50)
    print("DES CORE IMPLEMENTATION TESTS COMPLETED")
    print("=" * 50)
    print("All core tests passed:", all_tests_passed)

    # Text Encryption Tests
    print("\n" + "=" * 50)
    print("TEXT ENCRYPTION VERIFICATION")
    print("=" * 50)

    test_key_hex = "133457799BBCDFF1"

    test_messages = [
        "Hello DES Security Lab!",
        "Cybersecurity is interesting.",
        "مرحبا، هذا اختبار لخوارزمية DES."
    ]

    for index, original_text in enumerate(test_messages, start=1):

        encrypted = encrypt_text(original_text, test_key_hex)

        decrypted = decrypt_text(encrypted, test_key_hex)

        print(f"\n[TEXT TEST {index}]")
        print("Original:", original_text)
        print("Encrypted:", encrypted)
        print("Decrypted:", decrypted)
        print("Successful:", original_text == decrypted)
