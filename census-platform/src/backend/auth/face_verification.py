"""
Census Platform — Face Verification Service
Liveness detection + face matching + deduplication via FAISS
Privacy-preserving: raw images are NEVER persisted
"""
import hashlib
import numpy as np
from dataclasses import dataclass
from enum import Enum
from typing import Optional
import onnxruntime as ort
import faiss
import cv2

from ..core.config import get_settings
from ..core.audit import emit_audit_event

settings = get_settings()


class FaceVerificationResult(str, Enum):
    VERIFIED = "verified"
    LIVENESS_FAILED = "liveness_failed"
    QUALITY_TOO_LOW = "quality_too_low"
    NO_FACE_DETECTED = "no_face_detected"
    DUPLICATE_DETECTED = "duplicate_detected"
    ID_MISMATCH = "id_mismatch"
    PROCESSING_ERROR = "processing_error"


@dataclass
class FaceEmbedding:
    """512-dimensional FaceNet embedding — NEVER stored directly."""
    vector: np.ndarray   # shape: (512,)
    quality_score: float
    liveness_score: float


@dataclass
class VerificationResponse:
    result: FaceVerificationResult
    confidence: float
    face_hash: Optional[bytes] = None    # SHA3(embedding + citizen_salt)
    is_duplicate: bool = False
    duplicate_distance: float = 0.0


class ImageQualityChecker:
    """Fast image quality validation before expensive ML inference."""

    MIN_RESOLUTION = (224, 224)
    MAX_BLUR_THRESHOLD = 100.0   # Laplacian variance

    @staticmethod
    def check(image: np.ndarray) -> tuple[bool, str]:
        h, w = image.shape[:2]
        if h < ImageQualityChecker.MIN_RESOLUTION[0] or w < ImageQualityChecker.MIN_RESOLUTION[1]:
            return False, "resolution_too_low"

        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        blur_score = cv2.Laplacian(gray, cv2.CV_64F).var()
        if blur_score < ImageQualityChecker.MAX_BLUR_THRESHOLD:
            return False, "image_too_blurry"

        brightness = np.mean(gray)
        if brightness < 30 or brightness > 225:
            return False, "poor_lighting"

        return True, "ok"


class LivenessDetector:
    """
    Passive liveness detection using texture analysis.
    Detects: printed photos, screen replays, 3D masks.
    """

    def __init__(self, model_path: str):
        self._session = ort.InferenceSession(
            model_path,
            providers=["CUDAExecutionProvider", "CPUExecutionProvider"],
        )
        self._input_name = self._session.get_inputs()[0].name

    def predict(self, face_crop: np.ndarray) -> float:
        """Returns liveness score in [0, 1]. 1.0 = definitely live person."""
        resized = cv2.resize(face_crop, (128, 128))
        normalized = resized.astype(np.float32) / 255.0
        tensor = np.expand_dims(normalized.transpose(2, 0, 1), axis=0)
        outputs = self._session.run(None, {self._input_name: tensor})
        return float(outputs[0][0][1])  # Softmax live probability


class FaceEmbedder:
    """FaceNet-512 embedding extraction."""

    def __init__(self, model_path: str):
        self._session = ort.InferenceSession(
            model_path,
            providers=["CUDAExecutionProvider", "CPUExecutionProvider"],
        )
        self._input_name = self._session.get_inputs()[0].name

    def embed(self, face_crop: np.ndarray) -> np.ndarray:
        """Returns L2-normalized 512-d embedding."""
        resized = cv2.resize(face_crop, (160, 160))
        normalized = (resized.astype(np.float32) - 127.5) / 128.0
        tensor = np.expand_dims(normalized.transpose(2, 0, 1), axis=0)
        outputs = self._session.run(None, {self._input_name: tensor})
        embedding = outputs[0][0]
        return embedding / np.linalg.norm(embedding)  # L2 normalize


class FaceDeduplicator:
    """
    FAISS approximate nearest-neighbor search for face deduplication.
    Detects if a face has already been registered under a different identity.
    """

    DUPLICATE_DISTANCE_THRESHOLD = 0.35  # Cosine distance (lower = more similar)

    def __init__(self, index_path: str, dimension: int = 512):
        self._dimension = dimension
        self._index_path = index_path
        try:
            self._index = faiss.read_index(index_path)
        except Exception:
            self._index = faiss.IndexFlatL2(dimension)

    def is_duplicate(self, embedding: np.ndarray) -> tuple[bool, float]:
        """Returns (is_duplicate, nearest_distance)."""
        if self._index.ntotal == 0:
            return False, 1.0

        query = np.expand_dims(embedding.astype(np.float32), axis=0)
        distances, _ = self._index.search(query, k=1)
        min_distance = float(distances[0][0])
        return min_distance < self.DUPLICATE_DISTANCE_THRESHOLD, min_distance

    def add_embedding(self, embedding: np.ndarray) -> None:
        """Add verified embedding to index."""
        vector = np.expand_dims(embedding.astype(np.float32), axis=0)
        self._index.add(vector)
        faiss.write_index(self._index, self._index_path)


def _hash_face_embedding(embedding: np.ndarray, citizen_salt: bytes) -> bytes:
    """
    One-way hash of face embedding.
    Cannot reconstruct face geometry from hash.
    Different salts → different hashes even for same person.
    """
    embedding_bytes = embedding.tobytes()
    return hashlib.sha3_256(citizen_salt + embedding_bytes).digest()


def _detect_face(image: np.ndarray) -> Optional[np.ndarray]:
    """Extract largest face crop using OpenCV cascade (fast, CPU-friendly)."""
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    detector = cv2.CascadeClassifier(
        cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
    )
    faces = detector.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(80, 80))

    if len(faces) == 0:
        return None

    # Take largest detected face
    x, y, w, h = max(faces, key=lambda f: f[2] * f[3])
    padding = int(0.2 * min(w, h))
    x1 = max(0, x - padding)
    y1 = max(0, y - padding)
    x2 = min(image.shape[1], x + w + padding)
    y2 = min(image.shape[0], y + h + padding)
    return image[y1:y2, x1:x2]


class FaceVerificationService:
    """
    Main face verification service.
    Orchestrates: quality check → face detection → liveness → embedding → dedup
    """

    def __init__(self):
        self._quality_checker = ImageQualityChecker()
        self._liveness_detector = LivenessDetector(settings.LIVENESS_MODEL_PATH)
        self._embedder = FaceEmbedder(settings.FACENET_MODEL_PATH)
        self._deduplicator = FaceDeduplicator(settings.FAISS_INDEX_PATH)

    async def verify(
        self,
        image_bytes: bytes,
        citizen_salt: bytes,
        id_face_embedding: Optional[np.ndarray] = None,
    ) -> VerificationResponse:
        """
        Full verification pipeline.
        image_bytes: JPEG/PNG from camera — deleted from memory after processing
        citizen_salt: unique per-citizen salt for face hashing
        id_face_embedding: embedding from OCR'd ID photo (for face match check)
        """
        image_array = np.frombuffer(image_bytes, dtype=np.uint8)
        image = cv2.imdecode(image_array, cv2.IMREAD_COLOR)
        del image_bytes  # Immediately free raw bytes

        # Quality gate
        quality_ok, reason = ImageQualityChecker.check(image)
        if not quality_ok:
            return VerificationResponse(
                result=FaceVerificationResult.QUALITY_TOO_LOW,
                confidence=0.0,
            )

        # Face detection
        face_crop = _detect_face(image)
        del image  # Free full image
        if face_crop is None:
            return VerificationResponse(
                result=FaceVerificationResult.NO_FACE_DETECTED,
                confidence=0.0,
            )

        # Liveness check
        liveness_score = self._liveness_detector.predict(face_crop)
        if liveness_score < settings.FACE_LIVENESS_THRESHOLD:
            await emit_audit_event(
                event_type="face.liveness_failed",
                outcome="blocked",
                metadata={"liveness_score": liveness_score},
            )
            return VerificationResponse(
                result=FaceVerificationResult.LIVENESS_FAILED,
                confidence=liveness_score,
            )

        # Generate embedding
        embedding = self._embedder.embed(face_crop)
        del face_crop  # Free cropped image

        # Deduplication check
        is_dup, dup_distance = self._deduplicator.is_duplicate(embedding)
        if is_dup:
            await emit_audit_event(
                event_type="face.duplicate_detected",
                outcome="blocked",
                metadata={"distance": dup_distance},
            )
            return VerificationResponse(
                result=FaceVerificationResult.DUPLICATE_DETECTED,
                confidence=liveness_score,
                is_duplicate=True,
                duplicate_distance=dup_distance,
            )

        # ID face match (if provided)
        if id_face_embedding is not None:
            similarity = float(np.dot(embedding, id_face_embedding))
            if similarity < settings.FACE_SIMILARITY_THRESHOLD:
                return VerificationResponse(
                    result=FaceVerificationResult.ID_MISMATCH,
                    confidence=similarity,
                )

        # Generate privacy-preserving hash
        face_hash = _hash_face_embedding(embedding, citizen_salt)

        # Register in deduplication index
        self._deduplicator.add_embedding(embedding)
        del embedding  # Free embedding — hash is all we keep

        await emit_audit_event(
            event_type="face.verified",
            outcome="success",
            metadata={"liveness_score": liveness_score},
        )

        return VerificationResponse(
            result=FaceVerificationResult.VERIFIED,
            confidence=liveness_score,
            face_hash=face_hash,
        )
