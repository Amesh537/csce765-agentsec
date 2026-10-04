import struct

from handshake import build_transcript, create_demo_parties, parse_transcript, run_handshake


def test_valid_handshake():
    gateway, node = create_demo_parties()
    gateway_keys, node_keys = run_handshake(gateway, node)

    assert gateway_keys == node_keys
    assert gateway_keys is not node_keys
    assert len(gateway_keys.session_id) == 8

    keys = (
        gateway_keys.gateway_to_node_encryption_key,
        gateway_keys.gateway_to_node_mac_key,
        gateway_keys.node_to_gateway_encryption_key,
        gateway_keys.node_to_gateway_mac_key,
    )
    assert all(len(key) == 32 for key in keys)
    assert len(set(keys)) == 4


def test_fresh_sessions():
    gateway, node = create_demo_parties()
    hellos = {}

    def capture(stage, message):
        if stage in ("gateway_hello", "node_hello"):
            hellos[stage] = message
        return message

    first, first_peer = run_handshake(gateway, node, capture)
    first_hellos = hellos.copy()
    second, second_peer = run_handshake(gateway, node, capture)

    assert first == first_peer
    assert second == second_peer
    for stage in ("gateway_hello", "node_hello"):
        assert first_hellos[stage].nonce != hellos[stage].nonce
        assert first_hellos[stage].ephemeral_dh_public_value != hellos[stage].ephemeral_dh_public_value

    for name in (
        "gateway_to_node_encryption_key",
        "gateway_to_node_mac_key",
        "node_to_gateway_encryption_key",
        "node_to_gateway_mac_key",
        "session_id",
    ):
        assert getattr(first, name) != getattr(second, name)


def test_transcript_encoding():
    gateway, node = create_demo_parties()
    gateway_hello, node_hello = gateway.start_session(), node.start_session()
    for hello in (gateway_hello, node_hello):
        assert len(hello.ephemeral_dh_public_value) == 384
        assert len(hello.nonce) == 16

    fields = (
        (13, b"CSCE465-HS-v2"),
        (9, b"ffdhe3072"),
        (7, b"gateway"),
        (4, b"node"),
        (384, gateway_hello.ephemeral_dh_public_value),
        (384, node_hello.ephemeral_dh_public_value),
        (16, gateway_hello.nonce),
        (16, node_hello.nonce),
    )
    expected = b"".join(struct.pack(">I", size) + value for size, value in fields)
    transcript = build_transcript(gateway_hello, node_hello)
    assert transcript == expected
    assert parse_transcript(transcript, expected_gateway_identity="gateway",
                            expected_node_identity="node") == (gateway_hello, node_hello)
