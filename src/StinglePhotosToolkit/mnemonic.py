from libnacl import crypto_scalarmult_base
from hashlib import sha256
from bitarray import bitarray
from .mnemonic_wordlist import words


def is_bit_set(n, k):
    return ((n >> k) & 1) == 1


def mnemonic_to_bits(memo: str):
    s = memo.split(" ")
    bit_array = bitarray()
    for w in s:
        if w not in words:
            raise ValueError(f"Invalid word: {w}")
        index = words[w]
        for i in range(11):
            bit_array.append(is_bit_set(index, 10 - i))
    return bit_array


def validate_key(entropy: bytes) -> bool:
    ent = len(entropy) * 8
    if ent < 128 or ent > 256 or ent % 32 != 0:
        raise ValueError("The allowed size of ENT is 128-256 bits of multiples of 32")


def calculate_checksum(entropy: bytes) -> bytes:
    ent = len(entropy) * 8
    mask = 0xFF << int(8 - ent / 32)
    bytes = sha256(entropy).digest()
    return bytes[0] & mask


def mnemonic_to_keys(memo: str) -> bytes:
    bits = mnemonic_to_bits(memo)
    if len(bits) == 0:
        raise ValueError("Empty mnemonic")
    ent = 32 * len(bits) / 33
    if ent % 8 != 0:
        raise ValueError(f"Wrong mnemonic size")
    ent_bytes = int(ent / 8)
    entropy = bits.tobytes()[:ent_bytes]
    validate_key(entropy)
    expected_checksum = calculate_checksum(entropy)
    actual_checksum = bits.tobytes()[ent_bytes]
    if expected_checksum != actual_checksum:
        raise ValueError("Wrong checksum")
    public_key = crypto_scalarmult_base(entropy)
    return public_key, entropy
