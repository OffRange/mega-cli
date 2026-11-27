"""Synthetic MEGA MPI and raw-RSA vectors; no account or network required."""

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from mega_cli.crypto import (
    MegaPrivateKey,
    MPIFormatError,
    PrivateKeyError,
    SessionDecryptionError,
    base64url_decode,
    base64url_encode,
    decrypt_private_key,
    decrypt_session_id,
    parse_mpis,
    wrap_key,
)


def encode_mpi(value: int) -> bytes:
    """Independent test-only MPI encoder."""
    bits = value.bit_length()
    return bits.to_bytes(2, "big") + value.to_bytes((bits + 7) // 8, "big")


@pytest.fixture(scope="module")
def key_numbers() -> rsa.RSAPrivateNumbers:
    private = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    return private.private_numbers()


@pytest.fixture
def test_key(
    key_numbers: rsa.RSAPrivateNumbers,
) -> MegaPrivateKey:
    return MegaPrivateKey(
        key_numbers.p,
        key_numbers.q,
        key_numbers.d,
    )


@pytest.mark.parametrize(
    "values",
    [(0,), (1, 255, 256, 65537), (2**127, 2**128 - 1)],
)
def test_mpi_roundtrip(values: tuple[int, ...]) -> None:
    encoded = b"".join(encode_mpi(v) for v in values)
    assert parse_mpis(encoded, len(values)) == values


def test_mpi_padding() -> None:
    assert parse_mpis(encode_mpi(123) + bytes(15), 1) == (123,)


@pytest.mark.parametrize(
    "bad",
    [b"", b"\x00", b"\x00\x08", b"\x00\x08\x00", b"\x00\x08\x01X"],
)
def test_invalid_mpi_raises_specific_error(bad: bytes) -> None:
    with pytest.raises(MPIFormatError):
        parse_mpis(bad, 1)


def test_truncated_second_mpi() -> None:
    with pytest.raises(MPIFormatError, match="MPI 2"):
        parse_mpis(encode_mpi(123) + b"\x00", 2)


def test_reject_excess_padding_and_nonzero_padding() -> None:
    for extra in (b"\x01", bytes(16)):
        with pytest.raises(MPIFormatError):
            parse_mpis(encode_mpi(123) + extra, 1)


def test_private_key_aes_decryption_and_repr(key_numbers: rsa.RSAPrivateNumbers) -> None:
    master = bytes(range(16))
    p, q, d = key_numbers.p, key_numbers.q, key_numbers.d
    u = pow(p, -1, q)
    raw = b"".join(encode_mpi(n) for n in (p, q, d, u))
    raw += bytes(-len(raw) % 16)
    encrypted = base64url_encode(wrap_key(raw, master))
    parsed = decrypt_private_key(encrypted, master)
    assert (parsed.p, parsed.q, parsed.d) == (p, q, d)
    assert str(p) not in repr(parsed)
    assert str(q) not in repr(parsed)
    assert str(d) not in repr(parsed)


def test_u_is_not_interpreted(key_numbers: rsa.RSAPrivateNumbers) -> None:
    p, q, d = key_numbers.p, key_numbers.q, key_numbers.d
    raw = b"".join(encode_mpi(n) for n in (p, q, d, 1))
    raw += bytes(-len(raw) % 16)
    master = b"Z" * 16
    assert decrypt_private_key(base64url_encode(wrap_key(raw, master)), master).d == d


def test_invalid_private_key() -> None:
    for encrypted in ("!!!", base64url_encode(b"short"), base64url_encode(bytes(16))):
        with pytest.raises(PrivateKeyError):
            decrypt_private_key(encrypted, bytes(16))


@pytest.mark.parametrize("prefix", [b"\x00\x00", b"\x00\x00\x00\x01", b"ABCD"])
def test_raw_rsa_sid_preserves_leading_zeros(
    prefix: bytes, key_numbers: rsa.RSAPrivateNumbers, test_key: MegaPrivateKey
) -> None:
    sid = prefix + b"S" * (43 - len(prefix))
    width = (key_numbers.p.bit_length() + 7) // 8 + (key_numbers.q.bit_length() + 7) // 8 - 2
    plaintext = sid.ljust(width, b"\0")
    m = int.from_bytes(plaintext, "big")
    n = key_numbers.p * key_numbers.q
    assert m < n
    csid = encode_mpi(pow(m, key_numbers.public_numbers.e, n))
    assert base64url_decode(decrypt_session_id(base64url_encode(csid), test_key)) == sid


def test_invalid_csid_and_out_of_range(test_key: MegaPrivateKey) -> None:
    for value in (
        "!",
        base64url_encode(b"\x01"),
        base64url_encode(encode_mpi(test_key.p * test_key.q)),
    ):
        with pytest.raises(SessionDecryptionError):
            decrypt_session_id(value, test_key)


def test_private_key_invalid_component() -> None:
    master = bytes(range(16))
    raw = b"".join(encode_mpi(x) for x in (1, 23, 17, 1))
    raw += bytes(-len(raw) % 16)
    with pytest.raises(PrivateKeyError):
        decrypt_private_key(base64url_encode(wrap_key(raw, master)), master)
