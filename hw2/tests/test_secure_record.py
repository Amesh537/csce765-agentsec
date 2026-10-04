import hmac
import struct

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from handshake import GATEWAY, NODE, create_demo_parties, run_handshake
import secure_record as sr


@pytest.fixture(scope="module")
def parties():
    return create_demo_parties()


@pytest.fixture
def session(parties):
    gateway_keys, node_keys = run_handshake(*parties)
    return sr.Endpoint(gateway_keys, GATEWAY), sr.Endpoint(node_keys, NODE), gateway_keys


def check_rejection(endpoint, record, reason, monkeypatch):
    counters = endpoint.send_sequence, endpoint.receive_sequence

    def no_decrypt(*args, **kwargs):
        pytest.fail("Rejected record reached decryption")

    with monkeypatch.context() as patch:
        patch.setattr(sr, "Cipher", no_decrypt)
        with pytest.raises(sr.RecordError, match=f"^{reason}$"):
            endpoint.open_record(record)
    assert (endpoint.send_sequence, endpoint.receive_sequence) == counters


def test_bidirectional_messages(session):
    gateway, node, _ = session
    command = b'{"action":"READ","path":"notes.txt"}'
    for sender, receiver, direction, sequence, message in (
        (gateway, node, 0, 0, command),
        (gateway, node, 0, 1, b"next"),
        (node, gateway, 1, 0, b"OK"),
        (node, gateway, 1, 1, b""),
        (gateway, node, 0, 2, b"last"),
    ):
        record = sender.seal(message)
        assert struct.unpack(">BBQBI", record[:15]) == (1, direction, sequence, 1, len(message))
        assert receiver.open_record(record) == message
    assert (gateway.send_sequence, gateway.receive_sequence) == (3, 2)
    assert (node.send_sequence, node.receive_sequence) == (2, 3)


def test_record_format(session):
    gateway, node, keys = session
    message = b"A" * 34
    for sender, receiver, direction, enc_key, mac_key in (
        (gateway, node, 0, keys.gateway_to_node_encryption_key, keys.gateway_to_node_mac_key),
        (node, gateway, 1, keys.node_to_gateway_encryption_key, keys.node_to_gateway_mac_key),
    ):
        for sequence in (0, 1):
            header = struct.pack(">BBQBI", 1, direction, sequence, 1, len(message))
            iv = keys.session_id + sequence.to_bytes(8, "big")
            encryptor = Cipher(algorithms.AES256(enc_key), modes.CTR(iv)).encryptor()
            ciphertext = encryptor.update(message) + encryptor.finalize()
            tag = hmac.digest(mac_key, header + iv + ciphertext, "sha256")
            record = sender.seal(message)
            assert record == header + ciphertext + tag
            assert len(record) == 15 + len(message) + 32
            assert receiver.open_record(record) == message


@pytest.mark.parametrize("offset,reason", [
    (0, "MAC"), (1, "MAC"), (9, "MAC"), (10, "MAC"),
    (14, "length"), (15, "MAC"), (-1, "MAC"),
], ids=["version", "direction", "sequence", "type", "length", "ciphertext", "tag"])
def test_modified_record(session, monkeypatch, offset, reason):
    gateway, node, _ = session
    record = gateway.seal(b"hello")
    changed = bytearray(record)
    changed[offset] ^= 1
    check_rejection(node, bytes(changed), reason, monkeypatch)
    assert node.open_record(record) == b"hello"


@pytest.mark.parametrize("field,value,reason", [
    (0, 2, "version"), (1, 1, "direction"), (2, 1, "sequence"), (3, 2, "message type"),
], ids=["version", "direction", "sequence", "type"])
def test_authenticated_invalid_header(session, monkeypatch, field, value, reason):
    gateway, node, keys = session
    record = gateway.seal(b"hello")
    fields = list(struct.unpack(">BBQBI", record[:15]))
    fields[field] = value
    header = struct.pack(">BBQBI", *fields)
    iv = keys.session_id + fields[2].to_bytes(8, "big")
    ciphertext = record[15:-32]
    tag = hmac.digest(keys.gateway_to_node_mac_key, header + iv + ciphertext, "sha256")
    check_rejection(node, header + ciphertext + tag, reason, monkeypatch)
    assert node.open_record(record) == b"hello"


@pytest.mark.parametrize("case", ["replay", "reflection", "out_of_order", "other_session"])
def test_wrong_record(session, parties, monkeypatch, case):
    gateway, node, _ = session
    first = gateway.seal(b"first")
    if case == "replay":
        assert node.open_record(first) == b"first"
        check_rejection(node, first, "sequence", monkeypatch)
        assert node.open_record(gateway.seal(b"next")) == b"next"
    elif case == "reflection":
        check_rejection(gateway, first, "MAC", monkeypatch)
        assert node.open_record(first) == b"first"
        assert gateway.open_record(node.seal(b"reply")) == b"reply"
    elif case == "out_of_order":
        second = gateway.seal(b"second")
        check_rejection(node, second, "sequence", monkeypatch)
        assert node.open_record(first) == b"first"
        assert node.open_record(second) == b"second"
    else:
        gkeys, nkeys = run_handshake(*parties)
        other_gateway, other_node = sr.Endpoint(gkeys, GATEWAY), sr.Endpoint(nkeys, NODE)
        check_rejection(other_node, first, "MAC", monkeypatch)
        assert other_node.open_record(other_gateway.seal(b"new session")) == b"new session"


def test_malformed_lengths(session, monkeypatch):
    gateway, node, _ = session
    record = gateway.seal(b"hello")
    for bad in [record[:end] for end in range(len(record))] + [record + b"extra"]:
        check_rejection(node, bad, "length", monkeypatch)
    assert node.open_record(record) == b"hello"


def test_send_limits(session):
    gateway, node, _ = session
    with pytest.raises(sr.RecordError, match="^message type$"):
        gateway.seal(b"hello", message_type=2)
    assert gateway.send_sequence == 0
    assert node.open_record(gateway.seal(b"hello")) == b"hello"

    # Counter boundary
    gateway.send_sequence = node.receive_sequence = (1 << 64) - 1
    assert node.open_record(gateway.seal(b"last")) == b"last"
    assert gateway.send_sequence == node.receive_sequence == 1 << 64
    with pytest.raises(sr.RecordError, match="^sequence exhausted$"):
        gateway.seal(b"wrap")
    assert gateway.send_sequence == 1 << 64
