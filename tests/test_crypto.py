"""Known-answer and round-trip tests for the shared MEGA crypto helpers."""

import pytest

from mega_cli.crypto import (
    base64url_decode,
    base64url_encode,
    derive_v2_login_keys,
    unwrap_key,
    wrap_key,
)



class TestBase64URL(pytest.TestCase.assertEqual):
    def test_vectors_and_padding(self)-> None:
        # RFC 4648 example with URL-safe substitutions and omitted padding.
        self.assertEqual(base64url_encode(b"foo"), "Zm9v")
        self.assertEqual(base64url_encode(b"f"), "Zg")
        self.assertEqual(base64url_encode(bytes([0xFB, 0xFF])), "-_8")
        for value in ("Zg", "Zg=="):
            self.assertEqual(base64url_decode(value), b"f")
        for value in ("-_8", "-_8="):
            self.assertEqual(base64url_decode(value), bytes([0xFB, 0xFF]))
        self.assertEqual(base64url_decode(""), b"")

    def test_round_trip(self)-> None:
        for length in range(0, 80):
            data = bytes(range(length))
            self.assertEqual(base64url_decode(base64url_encode(data)), data)

    def test_invalid_strings(self) -> None:
        for value in ("A", "Zg===", "Z=g", "Zg=", "Zg!!", "Z h", "é", "Zh"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                base64url_decode(value)


class TestAesWrapping(pytest.TestCase.assertEqual):
    def test_nist_aes128_ecb_known_answer(self)-> None:
        # NIST SP 800-38A, F.1.1 AES-128 ECB, block 1.
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        plain = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
        cipher = bytes.fromhex("3ad77bb40d7a3660a89ecaf32466ef97")
        self.assertEqual(wrap_key(plain, key), cipher)
        self.assertEqual(unwrap_key(cipher, key), plain)

    def test_multiblock_round_trip(self)-> None:
        wrapping_key = bytes(range(16))
        for length in (16, 32, 48, 64):
            plain = bytes(range(length))
            self.assertEqual(unwrap_key(wrap_key(plain, wrapping_key), wrapping_key), plain)

    def test_rejects_invalid_lengths(self)-> None:
        for data, key in ((b"", b"0" * 16), (b"x" * 17, b"0" * 16), (b"0" * 16, b"x" * 24)):
            with self.assertRaises(ValueError):
                wrap_key(data, key)
            with self.assertRaises(ValueError):
                unwrap_key(data, key)


class TestV2Derivation(pytest.TestCase.assertEqual):
    def test_independently_calculated_openssl_vector(self)-> None:
        # Generated independently using OpenSSL CLI:
        # openssl kdf -keylen 32 -kdfopt digest:SHA512 \
        #   -kdfopt 'pass:correct horse battery staple' \
        #   -kdfopt hexsalt:30313233343536373839616263646566 \
        #   -kdfopt iter:100000 PBKDF2
        expected = bytes.fromhex("148d4da378346638841b2b47f90f79579febf1e5838ffcb0e8e21ab300236b01")
        result = derive_v2_login_keys("correct horse battery staple", b"0123456789abcdef")
        self.assertEqual(result.password_key, expected[:16])
        self.assertEqual(base64url_decode(result.user_hash), expected[16:])
        self.assertFalse(result.user_hash.endswith("="))

    def test_rejects_empty_salt(self)-> None:
        with self.assertRaises(ValueError):
            derive_v2_login_keys("secret", b"")


if __name__ == "__main__":
    pytest.main()
