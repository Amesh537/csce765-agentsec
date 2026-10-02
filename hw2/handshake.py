import os
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import dh, padding, rsa


PROTOCOL_LABEL = b"CSCE465-HS-v2"
GROUP_ID = b"ffdhe3072"
DH_VALUE_WIDTH = 384
NONCE_LENGTH = 16
GATEWAY, NODE = "gateway", "node"
GROUP_FILE = Path(__file__).with_name("ffdhe3072.pem")
# Standard group
FFDHE3072_MODULUS_HASH = bytes.fromhex(
    "0eaf67db3a839156d5013494a5318a772b5697d270d721f37f092efc69ea5a17"
)
SIGNATURE_PADDING = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH
)


@dataclass(frozen=True)
class HelloMessage:
    identity: str
    ephemeral_dh_public_value: bytes
    nonce: bytes


@dataclass(frozen=True)
class AuthenticationMessage:
    encoded_transcript: bytes
    signature: bytes


@dataclass(frozen=True)
class SessionKeys:
    gateway_to_node_encryption_key: bytes = field(repr=False)
    gateway_to_node_mac_key: bytes = field(repr=False)
    node_to_gateway_encryption_key: bytes = field(repr=False)
    node_to_gateway_mac_key: bytes = field(repr=False)
    session_id: bytes


class HandshakeError(ValueError):
    pass


def encode_field(value: bytes) -> bytes:
    return len(value).to_bytes(4, "big") + value


def build_transcript(gateway_hello: HelloMessage, node_hello: HelloMessage) -> bytes:
    # Gateway first
    fields = (PROTOCOL_LABEL, GROUP_ID,
              gateway_hello.identity.encode(), node_hello.identity.encode(),
              gateway_hello.ephemeral_dh_public_value, node_hello.ephemeral_dh_public_value,
              gateway_hello.nonce, node_hello.nonce)
    transcript = b"".join(encode_field(value) for value in fields)
    parse_transcript(transcript, expected_gateway_identity=gateway_hello.identity,
                     expected_node_identity=node_hello.identity)
    return transcript


def parse_transcript(encoded: bytes, *, expected_gateway_identity: str,
                     expected_node_identity: str) -> tuple[HelloMessage, HelloMessage]:
    fixed = [PROTOCOL_LABEL, GROUP_ID,
             expected_gateway_identity.encode(), expected_node_identity.encode()]
    sizes = [len(value) for value in fixed] + [DH_VALUE_WIDTH] * 2 + [NONCE_LENGTH] * 2
    if not isinstance(encoded, bytes):
        raise HandshakeError("transcript bytes")
    fields, offset = [], 0
    for size in sizes:
        if offset + 4 > len(encoded):
            raise HandshakeError("transcript length")
        length = int.from_bytes(encoded[offset:offset + 4], "big")
        offset += 4
        if length != size or offset + length > len(encoded):
            raise HandshakeError("transcript length")
        fields.append(encoded[offset:offset + length])
        offset += length
    if offset != len(encoded):
        raise HandshakeError("trailing bytes")
    if fields[:4] != fixed:
        raise HandshakeError("transcript fields")
    return (HelloMessage(expected_gateway_identity, fields[4], fields[6]),
            HelloMessage(expected_node_identity, fields[5], fields[7]))


def _sha256(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()


def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    mac = hmac.HMAC(key, hashes.SHA256())
    mac.update(data)
    return mac.finalize()


def load_group_parameters(path=GROUP_FILE):
    parameters = serialization.load_pem_parameters(Path(path).read_bytes())
    _check_group(parameters)
    return parameters


def _check_group(parameters):
    numbers = parameters.parameter_numbers()
    if numbers.p.bit_length() != 3072 or numbers.g != 2:
        raise HandshakeError("DH group")
    if _sha256(numbers.p.to_bytes(DH_VALUE_WIDTH, "big")) != FFDHE3072_MODULUS_HASH:
        raise HandshakeError("DH group")


def derive_keys(shared_secret: bytes, transcript: bytes, *, expected_gateway_identity: str,
                expected_node_identity: str) -> SessionKeys:
    # Validate before hashing
    parse_transcript(transcript, expected_gateway_identity=expected_gateway_identity,
                     expected_node_identity=expected_node_identity)
    if not 1 <= len(shared_secret) <= DH_VALUE_WIDTH or not any(shared_secret):
        raise HandshakeError("shared secret")
    z = shared_secret.rjust(DH_VALUE_WIDTH, b"\x00")
    th = _sha256(transcript)
    master = _sha256(b"CSCE465-KDF-v1" + z + th)
    return SessionKeys(
        _hmac_sha256(master, b"gateway-to-node encryption" + th),
        _hmac_sha256(master, b"gateway-to-node MAC" + th),
        _hmac_sha256(master, b"node-to-gateway encryption" + th),
        _hmac_sha256(master, b"node-to-gateway MAC" + th),
        _hmac_sha256(master, b"session identifier" + th)[:8],
    )


class Party:
    def __init__(self, identity, role, signing_key, expected_peer_identity,
                 trusted_peer_key, parameters):
        if role not in (GATEWAY, NODE) or not identity or not expected_peer_identity:
            raise HandshakeError("identity or role")
        if identity == expected_peer_identity:
            raise HandshakeError("duplicate identity")
        if signing_key.key_size != 3072 or trusted_peer_key.key_size != 3072:
            raise HandshakeError("RSA key size")
        _check_group(parameters)
        self._identity, self._role = identity, role
        self._peer_identity = expected_peer_identity
        self._peer_role = NODE if role == GATEWAY else GATEWAY
        self._signing_key, self._trusted_peer_key = signing_key, trusted_peer_key
        self._parameters = parameters
        self._phase = "idle"
        self._clear()

    def _clear(self):
        self._dh_private = self._shared_secret = self._own_hello = self._transcript = None

    def abort(self):
        self._clear()
        self._phase = "failed"

    def _reject(self, reason):
        self.abort()
        raise HandshakeError(reason)

    def _check(self, condition, reason):
        if not condition:
            self._reject(reason)

    def _expected_identities(self):
        gateway, node = self._identity, self._peer_identity
        if self._role == NODE:
            gateway, node = node, gateway
        return dict(expected_gateway_identity=gateway, expected_node_identity=node)

    def start_session(self) -> HelloMessage:
        self._check(self._phase in ("idle", "complete", "failed"), "state")
        self._clear()
        self._dh_private = self._parameters.generate_private_key()
        public = self._dh_private.public_key().public_numbers().y
        self._own_hello = HelloMessage(
            self._identity, public.to_bytes(DH_VALUE_WIDTH, "big"), os.urandom(NONCE_LENGTH))
        self._phase = "hello_sent"
        return self._own_hello

    def receive_peer_hello(self, message: HelloMessage):
        self._check(self._phase == "hello_sent", "state")
        self._check(isinstance(message, HelloMessage), "hello")
        self._check(message.identity == self._peer_identity, "identity")
        gateway, node = self._own_hello, message
        if self._role == NODE:
            gateway, node = node, gateway
        try:
            transcript = build_transcript(gateway, node)
        except HandshakeError as error:
            self._reject(str(error))
        try:
            public = dh.DHPublicNumbers(int.from_bytes(message.ephemeral_dh_public_value, "big"),
                                        self._parameters.parameter_numbers()).public_key()
            self._shared_secret = self._dh_private.exchange(public)
        except ValueError:
            self._reject("DH public value")
        self._transcript = transcript
        self._phase = "peer_hello_received"

    def make_authentication_message(self) -> AuthenticationMessage:
        expected = "peer_hello_received" if self._role == GATEWAY else "peer_authenticated"
        self._check(self._phase == expected, "state")
        signature = self._signing_key.sign(self._role.encode() + _sha256(self._transcript),
                                            SIGNATURE_PADDING, hashes.SHA256())
        self._phase = "auth_sent" if self._role == GATEWAY else "ready"
        return AuthenticationMessage(self._transcript, signature)

    def verify_peer_authentication(self, message: AuthenticationMessage):
        expected = "auth_sent" if self._role == GATEWAY else "peer_hello_received"
        self._check(self._phase == expected, "state")
        self._check(isinstance(message, AuthenticationMessage), "authentication")
        try:
            parse_transcript(message.encoded_transcript, **self._expected_identities())
        except HandshakeError as error:
            self._reject(str(error))
        self._check(message.encoded_transcript == self._transcript, "transcript mismatch")
        self._check(isinstance(message.signature, bytes), "signature")
        try:
            self._trusted_peer_key.verify(
                message.signature, self._peer_role.encode() + _sha256(message.encoded_transcript),
                SIGNATURE_PADDING, hashes.SHA256())
        except InvalidSignature:
            self._reject("signature")
        self._phase = "ready" if self._role == GATEWAY else "peer_authenticated"

    def finish_session(self) -> SessionKeys:
        self._check(self._phase == "ready", "state")
        keys = derive_keys(self._shared_secret, self._transcript, **self._expected_identities())
        self._clear()
        self._phase = "complete"
        return keys


def run_handshake(gateway: Party, node: Party, relay=None) -> tuple[SessionKeys, SessionKeys]:
    # Message boundaries
    def deliver(stage, message):
        return message if relay is None else relay(stage, message)

    try:
        gateway_hello, node_hello = gateway.start_session(), node.start_session()
        node.receive_peer_hello(deliver("gateway_hello", gateway_hello))
        gateway.receive_peer_hello(deliver("node_hello", node_hello))
        node.verify_peer_authentication(deliver("gateway_auth", gateway.make_authentication_message()))
        gateway.verify_peer_authentication(deliver("node_auth", node.make_authentication_message()))
        return gateway.finish_session(), node.finish_session()
    except Exception:
        gateway.abort()
        node.abort()
        raise


def create_demo_parties() -> tuple[Party, Party]:
    # Pinned peer keys
    parameters = load_group_parameters()
    gateway_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    node_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    return (Party(GATEWAY, GATEWAY, gateway_key, NODE, node_key.public_key(), parameters),
            Party(NODE, NODE, node_key, GATEWAY, gateway_key.public_key(), parameters))


def main():
    gateway, node = create_demo_parties()
    first, peer = run_handshake(gateway, node)
    assert first == peer
    keys = (first.gateway_to_node_encryption_key, first.gateway_to_node_mac_key,
            first.node_to_gateway_encryption_key, first.node_to_gateway_mac_key)
    assert len(set(keys)) == 4 and all(len(key) == 32 for key in keys)
    assert len(first.session_id) == 8
    print("Handshake passed; both parties derived matching keys.")
    print("Four distinct 32-byte keys; 8-byte session ID:", first.session_id.hex())
    second, peer = run_handshake(gateway, node)
    assert second == peer and second.session_id != first.session_id
    print("Second session passed with a new session ID:", second.session_id.hex())


if __name__ == "__main__":
    main()
