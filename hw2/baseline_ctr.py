"""Task 1: demonstrate AES-CTR bit flipping and replay without a MAC."""

import json
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


PLAINTEXT = b'{"action":"READ","path":"notes.txt"}'
ORIGINAL_ACTION = b"READ"
REPLACEMENT_ACTION = b"NOOP"
ACTION_OFFSET = PLAINTEXT.index(ORIGINAL_ACTION)


def xor_bytes(left: bytes, right: bytes) -> bytes:
    """XOR two equal-length byte strings."""
    return bytes(a ^ b for a, b in zip(left, right, strict=True))


def encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def relay(ciphertext: bytes) -> bytes:
    """Change a known action field without receiving the key or decrypting.

    CTR gives C = P XOR S. Applying the mask READ XOR NOOP to C
    makes the receiver recover NOOP at the same position.
    """
    mask = xor_bytes(ORIGINAL_ACTION, REPLACEMENT_ACTION)
    modified = bytearray(ciphertext)
    for index, change in enumerate(mask, start=ACTION_OFFSET):
        modified[index] ^= change
    return bytes(modified)


class Receiver:
    """Deliberately lacks authentication and replay tracking.

    Processing means parsing and printing a command, never accessing its path
    or executing its action.
    """

    def __init__(self, key: bytes):
        self.key = key
        self.processed_count = 0

    def receive(self, iv: bytes, ciphertext: bytes) -> dict:
        decryptor = Cipher(algorithms.AES(self.key), modes.CTR(iv)).decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        command = json.loads(plaintext)
        self.processed_count += 1
        print(f"Processed #{self.processed_count}: {plaintext.decode('utf-8')}")
        return command


def main() -> None:
    # Encrypt once using a fresh 256-bit key and 128-bit CTR IV.
    key = os.urandom(32)
    iv = os.urandom(16)
    ciphertext = encrypt(key, iv, PLAINTEXT)
    modified = relay(ciphertext)

    print(f"Assigned plaintext: {PLAINTEXT.decode('utf-8')}")
    print(f"IV: {iv.hex()}")
    print(f"Original ciphertext: {ciphertext.hex()}")
    print(f"Modified ciphertext: {modified.hex()}")

    print("\nBit-flip demonstration (no key supplied to relay)")
    mask = xor_bytes(ORIGINAL_ACTION, REPLACEMENT_ACTION)
    action_slice = slice(ACTION_OFFSET, ACTION_OFFSET + len(ORIGINAL_ACTION))
    original_bytes = ciphertext[action_slice]
    modified_bytes = modified[action_slice]
    print(f"Action byte offset: {ACTION_OFFSET}")
    print(f"READ XOR NOOP: {ORIGINAL_ACTION.hex()} XOR "
          f"{REPLACEMENT_ACTION.hex()} = {mask.hex()}")
    print(f"C XOR mask = C': {original_bytes.hex()} XOR "
          f"{mask.hex()} = {modified_bytes.hex()}")
    print("P' = (C XOR mask) XOR keystream = P XOR mask")
    tampered_command = Receiver(key).receive(iv, modified)
    assert tampered_command == {"action": "NOOP", "path": "notes.txt"}

    print("\nReplay demonstration (identical IV and original ciphertext sent twice)")
    receiver = Receiver(key)
    first = receiver.receive(iv, ciphertext)
    second = receiver.receive(iv, ciphertext)
    assert first == second == {"action": "READ", "path": "notes.txt"}
    assert receiver.processed_count == 2
    print(f"Receiver processed the same record {receiver.processed_count} times.")


if __name__ == "__main__":
    main()
