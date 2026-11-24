import pytest

from mega_cli.crypto import (
    base64url_decode, base64url_encode, derive_v2_login_keys, unwrap_key, wrap_key,
)


class TestBase64URL:
    def test_vectors_and_padding(self) -> None:
        assert base64url_encode(b"foo") == "Zm9v"
        assert base64url_encode(b"f") == "Zg"
        assert base64url_encode(bytes([0xFB, 0xFF])) == "-_8"
        for value in ("Zg", "Zg=="):
            assert base64url_decode(value) == b"f"
        for value in ("-_8", "-_8="):
            assert base64url_decode(value) == bytes([0xFB, 0xFF])
        assert base64url_decode("") == b""

    def test_round_trip(self) -> None:
        for length in range(80):
            data = bytes(range(length))
            assert base64url_decode(base64url_encode(data)) == data

    @pytest.mark.parametrize("value", ["A", "Zg===", "Z=g", "Zg=", "Zg!!", "Z h", "é", "Zh"])
    def test_invalid_strings(self, value: str) -> None:
        with pytest.raises(ValueError):
            base64url_decode(value)


class TestAesWrapping:
    def test_nist_aes128_ecb_known_answer(self) -> None:
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        plain = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
        cipher = bytes.fromhex("3ad77bb40d7a3660a89ecaf32466ef97")
        assert wrap_key(plain, key) == cipher
        assert unwrap_key(cipher, key) == plain

    @pytest.mark.parametrize("length", [16, 32, 48, 64])
    def test_multiblock_round_trip(self, length: int) -> None:
        wrapping_key = bytes(range(16))
        plain = bytes(range(length))
        assert unwrap_key(wrap_key(plain, wrapping_key), wrapping_key) == plain

    @pytest.mark.parametrize(
        ("data", "key"),
        [(b"", b"0" * 16), (b"x" * 17, b"0" * 16), (b"0" * 16, b"x" * 24)],
    )
    def test_rejects_invalid_lengths(self, data: bytes, key: bytes) -> None:
        with pytest.raises(ValueError):
            wrap_key(data, key)
        with pytest.raises(ValueError):
            unwrap_key(data, key)


class TestV2Derivation:
    def test_independently_calculated_openssl_vector(self) -> None:
        expected = bytes.fromhex("148d4da378346638841b2b47f90f79579febf1e5838ffcb0e8e21ab300236b01")
        result = derive_v2_login_keys("correct horse battery staple", b"0123456789abcdef")
        assert result.password_key == expected[:16]
        assert base64url_decode(result.user_hash) == expected[16:]
        assert not result.user_hash.endswith("=")

    def test_rejects_empty_salt(self) -> None:
        with pytest.raises(ValueError):
            derive_v2_login_keys("secret", b"")
