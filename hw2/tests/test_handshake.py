import hashlib
import hmac
import struct
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import handshake as hs


@pytest.fixture(scope="module")
def identities():
    parameters = hs.load_group_parameters()
    keys = [rsa.generate_private_key(public_exponent=65537, key_size=3072) for _ in range(3)]
    return parameters, keys


def make_parties(identities, wrong_key=False, shared_key=False):
    parameters, (gateway_key, node_key, other_key) = identities
    if shared_key:
        node_key = gateway_key
    trusted_node = other_key if wrong_key else node_key
    return (
        hs.Party("gateway", "gateway", gateway_key, "node", trusted_node.public_key(), parameters),
        hs.Party("node", "node", node_key, "gateway", gateway_key.public_key(), parameters),
    )


def test_valid_handshake(identities):
    gateway, node = make_parties(identities)
    messages = {}

    def capture(stage, message):
        messages[stage] = message
        return message

    gateway_keys, node_keys = hs.run_handshake(gateway, node, capture)
    assert gateway_keys == node_keys
    assert gateway_keys is not node_keys
    assert len(gateway_keys.session_id) == 8
    keys = (gateway_keys.gateway_to_node_encryption_key, gateway_keys.gateway_to_node_mac_key,
            gateway_keys.node_to_gateway_encryption_key, gateway_keys.node_to_gateway_mac_key)
    assert all(len(key) == 32 for key in keys)
    assert len(set(keys)) == 4

    # Check signed payloads
    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
    for role, key in zip(("gateway", "node"), identities[1][:2]):
        message = messages[role + "_auth"]
        payload = role.encode() + hashlib.sha256(message.encoded_transcript).digest()
        key.public_key().verify(message.signature, payload, pss, hashes.SHA256())


def test_fresh_sessions(identities):
    gateway, node = make_parties(identities)
    hellos = {}

    def capture(stage, message):
        if stage in ("gateway_hello", "node_hello"):
            hellos[stage] = message
        return message

    first, first_peer = hs.run_handshake(gateway, node, capture)
    first_hellos = hellos.copy()
    second, second_peer = hs.run_handshake(gateway, node, capture)
    assert first == first_peer
    assert second == second_peer
    for stage in ("gateway_hello", "node_hello"):
        assert first_hellos[stage].nonce != hellos[stage].nonce
        assert first_hellos[stage].ephemeral_dh_public_value != hellos[stage].ephemeral_dh_public_value
    for name in ("gateway_to_node_encryption_key", "gateway_to_node_mac_key",
                 "node_to_gateway_encryption_key", "node_to_gateway_mac_key", "session_id"):
        assert getattr(first, name) != getattr(second, name)


def test_transcript_encoding(identities):
    gateway, node = make_parties(identities)
    gateway_hello, node_hello = gateway.start_session(), node.start_session()
    for hello in (gateway_hello, node_hello):
        assert len(hello.ephemeral_dh_public_value) == 384
        assert len(hello.nonce) == 16
    fields = (
        (13, b"CSCE465-HS-v2"), (9, b"ffdhe3072"), (7, b"gateway"), (4, b"node"),
        (384, gateway_hello.ephemeral_dh_public_value), (384, node_hello.ephemeral_dh_public_value),
        (16, gateway_hello.nonce), (16, node_hello.nonce),
    )
    expected = b"".join(struct.pack(">I", size) + value for size, value in fields)
    transcript = hs.build_transcript(gateway_hello, node_hello)
    assert transcript == expected
    assert hs.parse_transcript(transcript, expected_gateway_identity="gateway",
                               expected_node_identity="node") == (gateway_hello, node_hello)


def test_key_derivation():
    gateway = hs.HelloMessage("gateway", (2).to_bytes(384, "big"), b"g" * 16)
    node = hs.HelloMessage("node", (3).to_bytes(384, "big"), b"n" * 16)
    transcript = hs.build_transcript(gateway, node)
    ids = dict(expected_gateway_identity="gateway", expected_node_identity="node")
    actual = hs.derive_keys(b"\x02", transcript, **ids)
    th = hashlib.sha256(transcript).digest()
    master = hashlib.sha256(b"CSCE465-KDF-v1" + bytes(383) + b"\x02" + th).digest()
    labels = (b"gateway-to-node encryption", b"gateway-to-node MAC",
              b"node-to-gateway encryption", b"node-to-gateway MAC", b"session identifier")
    outputs = [hmac.digest(master, label + th, "sha256") for label in labels]
    assert actual == hs.SessionKeys(*outputs[:4], outputs[4][:8])
    assert actual == hs.derive_keys(bytes(383) + b"\x02", transcript, **ids)
    assert actual != hs.derive_keys(b"\x03", transcript, **ids)
    changed = hs.build_transcript(replace(gateway, nonce=b"x" * 16), node)
    assert actual != hs.derive_keys(b"\x02", changed, **ids)


def test_malformed_transcript(identities, monkeypatch):
    gateway, node = make_parties(identities)
    gh, nh = gateway.start_session(), node.start_session()
    node.receive_peer_hello(gh)
    gateway.receive_peer_hello(nh)
    authentication = gateway.make_authentication_message()
    wire = authentication.encoded_transcript
    ids = dict(expected_gateway_identity="gateway", expected_node_identity="node")

    def no_hash(data):
        pytest.fail("Malformed transcript reached hashing")

    monkeypatch.setattr(hs, "_sha256", no_hash)
    cases = [(wire[:end], "transcript length") for end in range(len(wire))]
    cases += [(wire + b"extra", "trailing bytes"),
              (wire.replace(b"CSCE465-HS-v2", b"CSCE465-HS-v3", 1), "transcript fields"),
              (wire.replace(b"ffdhe3072", b"ffdhe2048", 1), "transcript fields"),
              (wire.replace(b"gateway", b"unknown", 1), "transcript fields")]
    offset = 0
    for size in (13, 9, 7, 4, 384, 384, 16, 16):
        bad = wire[:offset] + struct.pack(">I", size + 1) + wire[offset + 4:]
        cases.append((bad, "transcript length"))
        offset += 4 + size
    for bad, reason in cases:
        with pytest.raises(hs.HandshakeError, match=f"^{reason}$"):
            hs.parse_transcript(bad, **ids)
        with pytest.raises(hs.HandshakeError, match=f"^{reason}$"):
            hs.derive_keys(b"\x02", bad, **ids)
    with pytest.raises(hs.HandshakeError, match="^transcript length$"):
        node.verify_peer_authentication(replace(authentication, encoded_transcript=wire[:-1]))
    with pytest.raises(hs.HandshakeError, match="^state$"):
        node.finish_session()


@pytest.mark.parametrize("attack,stage,reason", [
    ("identity", "gateway_hello", "identity"),
    ("nonce", "gateway_hello", "transcript mismatch"),
    ("public_value", "node_hello", "transcript mismatch"),
    ("zero_public", "gateway_hello", "DH public value"),
    ("one_public", "node_hello", "DH public value"),
    ("signature", "gateway_auth", "signature"),
    ("short_signature", "node_auth", "signature"),
    ("wrong_key", "node_auth", "signature"),
    ("reflected_hello", "node_hello", "identity"),
    ("reflected_auth", "node_auth", "signature"),
    ("role_binding", "node_auth", "signature"),
    ("old_auth", "gateway_auth", "transcript mismatch"),
    ("old_hello", "gateway_hello", "transcript mismatch"),
    ("malformed", "gateway_auth", "transcript length"),
])
def test_handshake_rejection(identities, attack, stage, reason):
    old, current = {}, {}

    def capture(label, message):
        old[label] = message
        return message

    hs.run_handshake(*make_parties(identities), capture)
    gateway, node = make_parties(identities, wrong_key=attack == "wrong_key",
                                shared_key=attack == "role_binding")
    changes = {
        "identity": lambda m: replace(m, identity="imposter"),
        "nonce": lambda m: replace(m, nonce=bytes([m.nonce[0] ^ 1]) + m.nonce[1:]),
        "public_value": lambda m: replace(m, ephemeral_dh_public_value=old["node_hello"].ephemeral_dh_public_value),
        "zero_public": lambda m: replace(m, ephemeral_dh_public_value=bytes(384)),
        "one_public": lambda m: replace(m, ephemeral_dh_public_value=(1).to_bytes(384, "big")),
        "signature": lambda m: replace(m, signature=bytes([m.signature[0] ^ 1]) + m.signature[1:]),
        "short_signature": lambda m: replace(m, signature=m.signature[:-1]),
        "wrong_key": lambda m: m,
        "reflected_hello": lambda m: current["gateway_hello"],
        "reflected_auth": lambda m: current["gateway_auth"],
        "role_binding": lambda m: current["gateway_auth"],
        "old_auth": lambda m: old["gateway_auth"],
        "old_hello": lambda m: old["gateway_hello"],
        "malformed": lambda m: replace(m, encoded_transcript=b"\x00" * 4 + m.encoded_transcript[4:]),
    }

    def relay(label, message):
        current[label] = message
        return changes[attack](message) if label == stage else message

    with pytest.raises(hs.HandshakeError, match=f"^{reason}$"):
        hs.run_handshake(gateway, node, relay)
    for party in (gateway, node):
        with pytest.raises(hs.HandshakeError, match="^state$"):
            party.finish_session()
    if attack != "wrong_key":
        a, b = hs.run_handshake(gateway, node)
        assert a == b


@pytest.mark.parametrize("operation", [
    "premature_finish", "duplicate_hello", "duplicate_auth", "duplicate_finish", "early_signature",
])
def test_handshake_state(identities, operation):
    gateway, node = make_parties(identities)
    if operation == "premature_finish":
        action = gateway.finish_session
    elif operation == "duplicate_finish":
        hs.run_handshake(gateway, node)
        action = gateway.finish_session
    else:
        gh, nh = gateway.start_session(), node.start_session()
        if operation == "early_signature":
            action = gateway.make_authentication_message
        else:
            node.receive_peer_hello(gh)
            gateway.receive_peer_hello(nh)
            if operation == "duplicate_hello":
                action = lambda: node.receive_peer_hello(gh)
            else:
                authentication = gateway.make_authentication_message()
                node.verify_peer_authentication(authentication)
                action = lambda: node.verify_peer_authentication(authentication)
    with pytest.raises(hs.HandshakeError, match="^state$"):
        action()
    for party in (gateway, node):
        with pytest.raises(hs.HandshakeError, match="^state$"):
            party.finish_session()
    a, b = hs.run_handshake(gateway, node)
    assert a == b
