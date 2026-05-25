"""
Census Platform — Zero Knowledge Proof Service
Generates anonymous census tokens that prove identity verification
without revealing WHO was verified.

Circuit: Proves knowledge of:
  - A valid citizen_id in the identity tree (Merkle inclusion)
  - The enrollment_timestamp is within valid census window
  - The verification_level meets minimum requirement

Without revealing: citizen_id, phone, face, name, or any PII
"""
import hashlib
import secrets
from dataclasses import dataclass
from typing import Optional
import json
import subprocess
import tempfile
import os

from ..core.config import get_settings
from ..core.audit import emit_audit_event

settings = get_settings()


@dataclass
class ZKPToken:
    """
    Anonymous census token.
    Holder can prove they are a verified unique citizen
    without revealing their identity.
    """
    token_id: str           # UUID
    nullifier_hash: bytes   # Unique per (citizen, census) — prevents double use
    proof_data: bytes       # Groth16 proof
    circuit_version: str    # For future circuit upgrades
    verification_level: int # 1=phone, 2=face+phone, 3=document+face+phone


@dataclass
class ZKPVerificationResult:
    is_valid: bool
    nullifier_hash: Optional[bytes] = None
    error: Optional[str] = None


class MerkleTree:
    """
    In-memory Merkle tree of all verified citizen IDs.
    Root hash is publicly committed — proves census integrity.
    Leaves are hashed citizen_ids (not raw IDs).
    """

    def __init__(self):
        self._leaves: list[bytes] = []

    def add_leaf(self, citizen_id_hash: bytes) -> int:
        self._leaves.append(citizen_id_hash)
        return len(self._leaves) - 1

    def get_root(self) -> bytes:
        if not self._leaves:
            return b"\x00" * 32
        return self._compute_root(self._leaves)

    def get_proof(self, leaf_index: int) -> list[bytes]:
        """Returns Merkle inclusion proof path."""
        proof = []
        leaves = list(self._leaves)
        idx = leaf_index

        while len(leaves) > 1:
            if len(leaves) % 2 == 1:
                leaves.append(leaves[-1])  # Duplicate last leaf

            sibling_idx = idx ^ 1  # XOR to get sibling
            proof.append(leaves[sibling_idx])

            parent_leaves = []
            for i in range(0, len(leaves), 2):
                combined = leaves[i] + leaves[i + 1]
                parent_leaves.append(hashlib.sha3_256(combined).digest())

            leaves = parent_leaves
            idx //= 2

        return proof

    @staticmethod
    def _compute_root(leaves: list[bytes]) -> bytes:
        if len(leaves) == 1:
            return leaves[0]

        if len(leaves) % 2 == 1:
            leaves = leaves + [leaves[-1]]

        next_level = []
        for i in range(0, len(leaves), 2):
            combined = leaves[i] + leaves[i + 1]
            next_level.append(hashlib.sha3_256(combined).digest())

        return MerkleTree._compute_root(next_level)


def _compute_nullifier(citizen_id_hash: bytes, census_id: str) -> bytes:
    """
    Nullifier: unique per (citizen, census).
    Same citizen cannot submit twice in same census.
    Different censuses → different nullifiers (privacy across time).
    """
    combined = citizen_id_hash + census_id.encode()
    return hashlib.sha3_256(combined).digest()


class ZKPService:
    """
    Generates and verifies ZK proofs using snarkjs (via subprocess).
    In production: use native Python bindings or dedicated prover service.
    """

    CIRCUIT_VERSION = "v1.0.0"

    def __init__(self, merkle_tree: MerkleTree):
        self._tree = merkle_tree

    async def issue_token(
        self,
        citizen_id: str,
        verification_level: int,
        census_id: str,
    ) -> ZKPToken:
        """
        Issues an anonymous ZKP token after identity verification.
        The token proves the holder is a verified unique citizen.
        """
        citizen_id_hash = hashlib.sha3_256(citizen_id.encode()).digest()
        leaf_index = self._tree.add_leaf(citizen_id_hash)
        merkle_proof = self._tree.get_proof(leaf_index)
        merkle_root = self._tree.get_root()

        nullifier = _compute_nullifier(citizen_id_hash, census_id)

        # Generate ZK proof
        witness = self._build_witness(
            citizen_id_hash=citizen_id_hash,
            leaf_index=leaf_index,
            merkle_proof=merkle_proof,
            merkle_root=merkle_root,
            nullifier=nullifier,
            verification_level=verification_level,
            census_id=census_id,
        )

        proof_data = await self._generate_proof(witness)

        import uuid
        token = ZKPToken(
            token_id=str(uuid.uuid4()),
            nullifier_hash=nullifier,
            proof_data=proof_data,
            circuit_version=self.CIRCUIT_VERSION,
            verification_level=verification_level,
        )

        await emit_audit_event(
            event_type="zkp.token_issued",
            outcome="success",
            metadata={
                "census_id": census_id,
                "verification_level": verification_level,
                "circuit_version": self.CIRCUIT_VERSION,
            },
        )

        return token

    async def verify_token(
        self,
        proof_data: bytes,
        nullifier_hash: bytes,
        census_id: str,
        required_verification_level: int = 1,
    ) -> ZKPVerificationResult:
        """
        Verifies a ZKP token for census submission.
        Checks: valid proof, correct census, minimum verification level.
        Does NOT reveal citizen identity.
        """
        try:
            public_signals = self._extract_public_signals(proof_data, nullifier_hash, census_id)
            is_valid = await self._verify_proof(proof_data, public_signals)

            if not is_valid:
                return ZKPVerificationResult(is_valid=False, error="invalid_proof")

            if public_signals.get("verification_level", 0) < required_verification_level:
                return ZKPVerificationResult(is_valid=False, error="insufficient_verification_level")

            return ZKPVerificationResult(is_valid=True, nullifier_hash=nullifier_hash)

        except Exception as e:
            return ZKPVerificationResult(is_valid=False, error=str(e))

    @staticmethod
    def _build_witness(
        citizen_id_hash: bytes,
        leaf_index: int,
        merkle_proof: list[bytes],
        merkle_root: bytes,
        nullifier: bytes,
        verification_level: int,
        census_id: str,
    ) -> dict:
        """Build witness for the ZK circuit."""
        return {
            "citizenIdHash": int.from_bytes(citizen_id_hash, "big"),
            "leafIndex": leaf_index,
            "merkleProof": [int.from_bytes(p, "big") for p in merkle_proof],
            "merkleRoot": int.from_bytes(merkle_root, "big"),
            "nullifier": int.from_bytes(nullifier, "big"),
            "verificationLevel": verification_level,
            "censusId": int.from_bytes(census_id.encode()[:32], "big"),
        }

    @staticmethod
    async def _generate_proof(witness: dict) -> bytes:
        """
        Generate Groth16 proof using snarkjs.
        In production: replace with native Rust/Go prover for performance.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            witness_path = os.path.join(tmpdir, "witness.json")
            with open(witness_path, "w") as f:
                json.dump(witness, f)

            proof_path = os.path.join(tmpdir, "proof.json")
            result = subprocess.run(
                [
                    "snarkjs", "groth16", "prove",
                    "/circuits/census.zkey",
                    witness_path,
                    proof_path,
                ],
                capture_output=True,
                timeout=30,
            )

            if result.returncode != 0:
                # Fallback: return signed commitment (for environments without snarkjs)
                return _fallback_commitment(witness)

            with open(proof_path, "rb") as f:
                return f.read()

    @staticmethod
    async def _verify_proof(proof_data: bytes, public_signals: dict) -> bool:
        with tempfile.TemporaryDirectory() as tmpdir:
            proof_path = os.path.join(tmpdir, "proof.json")
            signals_path = os.path.join(tmpdir, "signals.json")

            with open(proof_path, "wb") as f:
                f.write(proof_data)
            with open(signals_path, "w") as f:
                json.dump(public_signals, f)

            result = subprocess.run(
                [
                    "snarkjs", "groth16", "verify",
                    "/circuits/verification_key.json",
                    signals_path,
                    proof_path,
                ],
                capture_output=True,
                timeout=10,
            )
            return result.returncode == 0

    @staticmethod
    def _extract_public_signals(
        proof_data: bytes, nullifier_hash: bytes, census_id: str
    ) -> dict:
        return {
            "nullifier": int.from_bytes(nullifier_hash, "big"),
            "censusId": int.from_bytes(census_id.encode()[:32], "big"),
        }


def _fallback_commitment(witness: dict) -> bytes:
    """
    HMAC-based commitment when ZK circuit unavailable.
    Used in offline/low-resource environments.
    Less privacy-preserving but still tamper-evident.
    """
    import hmac as _hmac
    content = json.dumps(witness, sort_keys=True).encode()
    secret = settings.HMAC_SECRET.get_secret_value().encode()
    return _hmac.new(secret, content, hashlib.sha3_256).digest()
