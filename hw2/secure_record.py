import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from handshake import GATEWAY, NODE, SessionKeys, create_demo_parties, run_handshake


VERSION = 1
APPLICATION_DATA = 1
GATEWAY_TO_NODE, NODE_TO_GATEWAY = 0, 1
HEADER = struct.Struct(">BBQBI")
HEADER_SIZE = HEADER.size
TAG_SIZE = 32
MAX_SEQUENCE = (1 << 64) - 1
MAX_LENGTH = (1 << 32) - 1


class RecordError(ValueError):
    pass


def _mac(key, data):
    mac = hmac.HMAC(key, hashes.SHA256())
    mac.update(data)
    return mac


class Endpoint:
    # One per session
    def __init__(self, session_keys: SessionKeys, role: str):
        g2n = (session_keys.gateway_to_node_encryption_key, session_keys.gateway_to_node_mac_key)
        n2g = (session_keys.node_to_gateway_encryption_key, session_keys.node_to_gateway_mac_key)
        if len(session_keys.session_id) != 8 or any(len(key) != 32 for key in g2n + n2g):
            raise RecordError("session keys")
        if role == GATEWAY:
            send, receive = g2n, n2g
            self.send_direction, self.receive_direction = GATEWAY_TO_NODE, NODE_TO_GATEWAY
        elif role == NODE:
            send, receive = n2g, g2n
            self.send_direction, self.receive_direction = NODE_TO_GATEWAY, GATEWAY_TO_NODE
        else:
            raise RecordError("role")
        self._send_enc, self._send_mac = send
        self._receive_enc, self._receive_mac = receive
        self.session_id = session_keys.session_id
        self.send_sequence = self.receive_sequence = 0

    def seal(self, plaintext: bytes, message_type=APPLICATION_DATA) -> bytes:
        if message_type != APPLICATION_DATA:
            raise RecordError("message type")
        if len(plaintext) > MAX_LENGTH:
            raise RecordError("length")
        if not 0 <= self.send_sequence <= MAX_SEQUENCE:
            raise RecordError("sequence exhausted")
        sequence = self.send_sequence
        iv = self.session_id + sequence.to_bytes(8, "big")
        encryptor = Cipher(algorithms.AES256(self._send_enc), modes.CTR(iv)).encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        header = HEADER.pack(VERSION, self.send_direction, sequence, message_type, len(ciphertext))
        tag = _mac(self._send_mac, header + iv + ciphertext).finalize()
        self.send_sequence += 1
        return header + ciphertext + tag

    def open_record(self, record: bytes) -> bytes:
        if len(record) < HEADER_SIZE + TAG_SIZE:
            raise RecordError("length")
        header = record[:HEADER_SIZE]
        version, direction, sequence, message_type, length = HEADER.unpack(header)
        if len(record) != HEADER_SIZE + length + TAG_SIZE:
            raise RecordError("length")
        ciphertext, tag = record[HEADER_SIZE:-TAG_SIZE], record[-TAG_SIZE:]
        iv = self.session_id + sequence.to_bytes(8, "big")

        # Verify first
        try:
            _mac(self._receive_mac, header + iv + ciphertext).verify(tag)
        except InvalidSignature:
            raise RecordError("MAC") from None
        if version != VERSION:
            raise RecordError("version")
        if direction != self.receive_direction:
            raise RecordError("direction")
        if message_type != APPLICATION_DATA:
            raise RecordError("message type")
        if sequence != self.receive_sequence:
            raise RecordError("sequence")

        decryptor = Cipher(algorithms.AES256(self._receive_enc), modes.CTR(iv)).decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        self.receive_sequence += 1
        return plaintext


def main():
    gateway_keys, node_keys = run_handshake(*create_demo_parties())
    gateway, node = Endpoint(gateway_keys, GATEWAY), Endpoint(node_keys, NODE)
    command = b'{"action":"READ","path":"notes.txt"}'
    for sender, receiver, label, message in (
        (gateway, node, "gateway -> node", command),
        (node, gateway, "node -> gateway", b"OK"),
        (gateway, node, "gateway -> node", command),
    ):
        sequence = sender.send_sequence
        record = sender.seal(message)
        received = receiver.open_record(record)
        assert received == message
        print(f"{label}, sequence {sequence}: {received.decode()}")
    print("Bidirectional messages and sequence checks passed.")


if __name__ == "__main__":
    main()
