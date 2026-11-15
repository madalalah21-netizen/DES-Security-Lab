
# ==================================================
# DES SECURITY LAB
# Flask Backend
# ==================================================

import time

from flask import Flask, render_template, request, jsonify

from des_engine import (
    encrypt_text,
    decrypt_text,
    encrypt_block,
    validate_key_hex,
    add_padding,
    BLOCK_SIZE
)

from brute_force import (
    brute_force_attack,
    candidate_to_des_key
)

from weak_keys import (
    WEAK_KEYS,
    SEMI_WEAK_PAIRS,
    test_weak_key,
    test_semi_weak_pair
)

from avalanche_effect import run_avalanche_analysis


app = Flask(__name__)


# ==================================================
# HOME PAGE
# ==================================================

@app.route("/")
def home():
    return render_template("index.html")


# ==================================================
# ENCRYPTION API
# ==================================================

@app.route("/api/encrypt", methods=["POST"])
def api_encrypt():

    try:
        data = request.get_json()

        if not isinstance(data, dict):
            raise ValueError("Invalid request data.")

        plaintext = data.get("plaintext", "")
        key_hex = data.get("key", "")

        if not plaintext:
            raise ValueError("Please enter plaintext.")

        if not key_hex:
            raise ValueError("Please enter an encryption key.")

        ciphertext = encrypt_text(plaintext, key_hex)

        return jsonify({
            "success": True,
            "ciphertext": ciphertext
        })

    except (ValueError, TypeError) as error:

        return jsonify({
            "success": False,
            "error": str(error)
        }), 400

    except Exception:

        app.logger.exception("Encryption error")

        return jsonify({
            "success": False,
            "error": "An internal encryption error occurred."
        }), 500


# ==================================================
# DECRYPTION API
# ==================================================

@app.route("/api/decrypt", methods=["POST"])
def api_decrypt():

    try:
        data = request.get_json()

        if not isinstance(data, dict):
            raise ValueError("Invalid request data.")

        ciphertext = data.get("ciphertext", "")
        key_hex = data.get("key", "")

        if not ciphertext:
            raise ValueError("Please enter ciphertext.")

        if not key_hex:
            raise ValueError("Please enter the decryption key.")

        plaintext = decrypt_text(ciphertext, key_hex)

        return jsonify({
            "success": True,
            "plaintext": plaintext
        })

    except (ValueError, TypeError) as error:

        return jsonify({
            "success": False,
            "error": str(error)
        }), 400

    except Exception:

        app.logger.exception("Decryption error")

        return jsonify({
            "success": False,
            "error": "An internal decryption error occurred."
        }), 500


# ==================================================
# ENCRYPTION ROUND TRACE API
# ==================================================

@app.route("/api/encrypt/trace", methods=["POST"])
def api_encrypt_trace():

    try:
        data = request.get_json()

        if not isinstance(data, dict):
            raise ValueError("Invalid request data.")

        plaintext = data.get("plaintext", "")
        key_hex = data.get("key", "")

        if not isinstance(plaintext, str) or not plaintext:
            raise ValueError("Please enter plaintext.")

        if not key_hex:
            raise ValueError("Please enter an encryption key.")

        key = validate_key_hex(key_hex)

        plaintext_bytes = plaintext.encode("utf-8")
        padded_data = add_padding(plaintext_bytes)

        ciphertext = encrypt_text(plaintext, key_hex)

        blocks = []

        for i in range(0, len(padded_data), BLOCK_SIZE):

            block_bytes = padded_data[i:i + BLOCK_SIZE]

            block_int = int.from_bytes(
                block_bytes,
                byteorder="big"
            )

            encrypted_int, trace = encrypt_block(
                block_int,
                key,
                return_trace=True
            )

            rounds = []

            for item in trace:

                rounds.append({
                    "round": item["round"],
                    "left": f'{item["left"]:08X}',
                    "right": f'{item["right"]:08X}',
                    "round_key": f'{item["round_key"]:012X}'
                })

            blocks.append({
                "block_number": len(blocks) + 1,
                "plaintext_block": block_bytes.hex().upper(),
                "ciphertext_block": f"{encrypted_int:016X}",
                "rounds": rounds
            })

        return jsonify({
            "success": True,
            "ciphertext": ciphertext,
            "total_blocks": len(blocks),
            "rounds_per_block": 16,
            "blocks": blocks
        })

    except (ValueError, TypeError) as error:

        return jsonify({
            "success": False,
            "error": str(error)
        }), 400

    except Exception:

        app.logger.exception("Round trace error")

        return jsonify({
            "success": False,
            "error": "An internal trace error occurred."
        }), 500


# ==================================================
# BRUTE FORCE ATTACK API
# ==================================================

@app.route("/api/brute-force", methods=["POST"])
def api_brute_force():

    try:
        data = request.get_json()

        if not isinstance(data, dict):
            raise ValueError("Invalid request data.")

        plaintext = data.get("plaintext", "")
        target_ciphertext = data.get("ciphertext", "")
        key_bits = data.get("key_bits")

        if not isinstance(plaintext, str) or not plaintext:
            raise ValueError("Please enter plaintext.")

        if not isinstance(target_ciphertext, str) or not target_ciphertext:
            raise ValueError("Please enter target ciphertext.")

        if isinstance(key_bits, bool) or not isinstance(key_bits, int):
            raise ValueError("Key size must be an integer.")

        if key_bits < 1 or key_bits > 24:
            raise ValueError(
                "Educational key size must be between 1 and 24 bits."
            )

        result = brute_force_attack(
            plaintext,
            target_ciphertext,
            key_bits
        )

        return jsonify(result)

    except (ValueError, TypeError) as error:

        return jsonify({
            "success": False,
            "error": str(error)
        }), 400

    except Exception:

        app.logger.exception("Brute force error")

        return jsonify({
            "success": False,
            "error": "An internal brute force error occurred."
        }), 500


# ==================================================
# KEY SIZE ANALYSIS API
# ==================================================

@app.route("/api/key-analysis", methods=["POST"])
def api_key_analysis():

    try:
        data = request.get_json()

        if not isinstance(data, dict):
            raise ValueError("Invalid request data.")

        plaintext = data.get("plaintext", "")

        if not isinstance(plaintext, str) or not plaintext:
            raise ValueError("Please enter plaintext.")

        # DES operates on one 8-byte block
        plaintext_bytes = plaintext.encode("utf-8")

        if len(plaintext_bytes) != BLOCK_SIZE:
            raise ValueError(
                "Plaintext must be exactly 8 bytes (64 bits). "
                "Use an 8-character ASCII plaintext."
            )

        # Convert plaintext into a 64-bit integer
        plaintext_block = int.from_bytes(
            plaintext_bytes,
            byteorder="big"
        )

        # Educational reduced key sizes
        key_sizes = [8, 12, 16, 20, 24]

        # Number of keys actually tested per size
        sample_size = 128

        results = []

        for key_bits in key_sizes:

            start_time = time.perf_counter()

            # Benchmark a limited sample
            for candidate in range(sample_size):

                key = candidate_to_des_key(
                    candidate,
                    key_bits
                )

                encrypt_block(
                    plaintext_block,
                    key
                )

            elapsed = time.perf_counter() - start_time

            # Actual measured average time per key
            average_time = elapsed / sample_size

            # Full reduced keyspace
            total_keys = 2 ** key_bits

            # Estimated full search time
            estimated_seconds = average_time * total_keys

            results.append({
                "key_bits": key_bits,
                "sample_size": sample_size,
                "total_keys": total_keys,
                "measured_seconds": round(elapsed, 8),
                "average_time_per_key": round(average_time, 10),
                "estimated_full_search_seconds": round(
                    estimated_seconds, 6
                ),
                "estimated_full_search_minutes": round(
                    estimated_seconds / 60, 4
                )
            })

        return jsonify({
            "success": True,
            "plaintext": plaintext,
            "sample_size": sample_size,
            "method": "Sample benchmark with linear full-search estimation",
            "results": results
        })

    except (ValueError, TypeError) as error:

        return jsonify({
            "success": False,
            "error": str(error)
        }), 400

    except Exception:

        app.logger.exception("Key size analysis error")

        return jsonify({
            "success": False,
            "error": "An internal key analysis error occurred."
        }), 500


# ==================================================
# WEAK AND SEMI-WEAK KEYS ANALYSIS API
# ==================================================

@app.route("/api/weak-keys", methods=["POST"])
def api_weak_keys():

    try:

        # Test all 4 standard DES weak keys
        weak_results = [
            test_weak_key(key)
            for key in WEAK_KEYS
        ]

        # Test all 6 standard semi-weak key pairs
        semi_results = [
            test_semi_weak_pair(key1, key2)
            for key1, key2 in SEMI_WEAK_PAIRS
        ]

        weak_passed = sum(
            result["passed"]
            for result in weak_results
        )

        semi_passed = sum(
            result["passed"]
            for result in semi_results
        )

        total_passed = weak_passed + semi_passed

        all_passed = (
            weak_passed == len(WEAK_KEYS)
            and semi_passed == len(SEMI_WEAK_PAIRS)
        )

        return jsonify({

            "success": all_passed,

            "test_plaintext": "0123456789ABCDEF",

            "weak_keys": weak_results,

            "semi_weak_pairs": semi_results,

            "weak_total": len(WEAK_KEYS),

            "weak_passed": weak_passed,

            "semi_total": len(SEMI_WEAK_PAIRS),

            "semi_passed": semi_passed,

            "total_tests": (
                len(WEAK_KEYS) + len(SEMI_WEAK_PAIRS)
            ),

            "total_passed": total_passed,

            "total_failed": (
                len(WEAK_KEYS) + len(SEMI_WEAK_PAIRS)
                - total_passed
            )

        })

    except Exception:

        app.logger.exception("Weak key analysis error")

        return jsonify({
            "success": False,
            "error": "An internal weak key analysis error occurred."
        }), 500


# ==================================================
# AVALANCHE EFFECT ANALYSIS API
# ==================================================

@app.route("/api/avalanche", methods=["POST"])
def api_avalanche():

    try:

        results = run_avalanche_analysis()

        return jsonify(results)

    except Exception:

        app.logger.exception("Avalanche effect analysis error")

        return jsonify({
            "success": False,
            "error": "An internal avalanche analysis error occurred."
        }), 500


# ==================================================
# RUN APPLICATION
# ==================================================

if __name__ == "__main__":

    app.run(debug=True)
