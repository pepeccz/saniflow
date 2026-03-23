"""Visual PII detector — face detection (YuNet) and signature heuristic.

Only active when sanitization level is ``strict``.  Gracefully degrades
when the YuNet ONNX model is unavailable (logs a warning, skips faces).
"""

from __future__ import annotations

import logging
from pathlib import Path

import cv2
import numpy as np

from app.config import settings
from app.models.extraction import ExtractionResult, ExtractedImage
from app.models.findings import BBox, EntityType, Finding, SanitizationLevel

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────

_YUNET_INPUT_SIZE = (320, 320)
_YUNET_SCORE_THRESHOLD = 0.9
_YUNET_NMS_THRESHOLD = 0.3
_YUNET_TOP_K = 5000

# Signature heuristic thresholds
_SIG_MIN_AREA_RATIO = 0.001      # min component area relative to image
_SIG_MAX_AREA_RATIO = 0.15       # max component area relative to image
_SIG_MIN_ASPECT_RATIO = 1.5      # width / height
_SIG_MAX_ASPECT_RATIO = 8.0
_SIG_MAX_DENSITY = 0.35           # max filled-pixel ratio (signatures are thin strokes)
_SIG_MIN_DENSITY = 0.02           # avoid noise specks


class VisualDetector:
    """Detects faces and signatures in extracted images.

    Face detection uses OpenCV's YuNet (``cv2.FaceDetectorYN``).
    Signature detection uses a connected-component analysis heuristic.

    Both detectors only run when *level* is ``strict``.
    """

    def __init__(self) -> None:
        self._face_detector: cv2.FaceDetectorYN | None = None
        self._yunet_available: bool | None = None  # None = not checked yet

    # ── Public API (satisfies Detector protocol) ─────────────────────

    def detect(
        self,
        extraction_result: ExtractionResult,
        level: SanitizationLevel,
    ) -> list[Finding]:
        """Detect visual PII in the extraction result's images.

        Args:
            extraction_result: Must contain ``images`` (list of ExtractedImage).
            level: Only ``strict`` triggers visual detection.

        Returns:
            Combined list of face and signature findings.
        """
        if level != SanitizationLevel.STRICT:
            return []

        findings: list[Finding] = []
        for image in extraction_result.images:
            mat = self._decode_image(image.content)
            if mat is None:
                logger.warning("Could not decode image on page %s — skipping", image.page)
                continue

            findings.extend(self._detect_faces(mat, image))
            findings.extend(self._detect_signatures(mat, image))

        logger.info("VisualDetector found %d visual entities", len(findings))
        return findings

    # ── Face detection (YuNet) ───────────────────────────────────────

    def _ensure_face_detector(self, width: int, height: int) -> cv2.FaceDetectorYN | None:
        """Lazily load the YuNet model.  Returns None if unavailable."""
        if self._yunet_available is False:
            return None

        model_path = settings.YUNET_MODEL_PATH
        if not Path(model_path).is_file():
            if self._yunet_available is None:
                logger.warning(
                    "YuNet model not found at '%s' — face detection disabled. "
                    "Download from https://github.com/opencv/opencv_zoo",
                    model_path,
                )
            self._yunet_available = False
            return None

        # Recreate detector when image size changes (YuNet needs exact size)
        self._face_detector = cv2.FaceDetectorYN.create(
            model=model_path,
            config="",
            input_size=(width, height),
            score_threshold=_YUNET_SCORE_THRESHOLD,
            nms_threshold=_YUNET_NMS_THRESHOLD,
            top_k=_YUNET_TOP_K,
        )
        self._yunet_available = True
        return self._face_detector

    def _detect_faces(self, mat: np.ndarray, image: ExtractedImage) -> list[Finding]:
        """Run YuNet face detection on a single image matrix."""
        h, w = mat.shape[:2]
        detector = self._ensure_face_detector(w, h)
        if detector is None:
            return []

        _, faces = detector.detect(mat)
        if faces is None:
            return []

        findings: list[Finding] = []
        for face in faces:
            # YuNet returns [x, y, w, h, ..., score] — 15 values per face
            x, y, fw, fh = face[0], face[1], face[2], face[3]
            score = float(face[14])

            # Translate bbox relative to image origin if image has a known
            # position on the page
            bbox = self._translate_bbox(x, y, fw, fh, image)

            findings.append(
                Finding(
                    entity_type=EntityType.FACE,
                    original_text=None,
                    score=score,
                    page=image.page,
                    bbox=bbox,
                ),
            )

        return findings

    # ── Signature detection (connected component heuristic) ──────────

    def _detect_signatures(self, mat: np.ndarray, image: ExtractedImage) -> list[Finding]:
        """Detect signature-like regions via connected component analysis.

        Heuristic: binarise → find connected components → filter by size,
        aspect ratio (wide/short), and pixel density (thin strokes).
        """
        gray = cv2.cvtColor(mat, cv2.COLOR_BGR2GRAY) if len(mat.shape) == 3 else mat
        h, w = gray.shape
        image_area = h * w

        if image_area == 0:
            return []

        # Adaptive threshold for varying lighting
        binary = cv2.adaptiveThreshold(
            gray,
            255,
            cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
            cv2.THRESH_BINARY_INV,
            blockSize=15,
            C=10,
        )

        # Morphological close to connect nearby strokes
        kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (5, 3))
        closed = cv2.morphologyEx(binary, cv2.MORPH_CLOSE, kernel, iterations=2)

        # Connected components
        num_labels, labels, stats, _centroids = cv2.connectedComponentsWithStats(
            closed, connectivity=8,
        )

        findings: list[Finding] = []
        for label_idx in range(1, num_labels):  # skip background (0)
            cx = stats[label_idx, cv2.CC_STAT_LEFT]
            cy = stats[label_idx, cv2.CC_STAT_TOP]
            cw = stats[label_idx, cv2.CC_STAT_WIDTH]
            ch = stats[label_idx, cv2.CC_STAT_HEIGHT]
            area = stats[label_idx, cv2.CC_STAT_AREA]

            # --- Filter by area relative to image ---
            area_ratio = area / image_area
            if area_ratio < _SIG_MIN_AREA_RATIO or area_ratio > _SIG_MAX_AREA_RATIO:
                continue

            # --- Filter by aspect ratio (signatures are wider than tall) ---
            if ch == 0:
                continue
            aspect = cw / ch
            if aspect < _SIG_MIN_ASPECT_RATIO or aspect > _SIG_MAX_ASPECT_RATIO:
                continue

            # --- Filter by pixel density (thin strokes → low density) ---
            component_area = cw * ch
            if component_area == 0:
                continue
            density = area / component_area
            if density < _SIG_MIN_DENSITY or density > _SIG_MAX_DENSITY:
                continue

            # Score proportional to how "signature-like" the shape is
            # Ideal aspect ~3:1, ideal density ~0.15
            aspect_score = 1.0 - min(abs(aspect - 3.0) / 3.0, 1.0)
            density_score = 1.0 - min(abs(density - 0.15) / 0.20, 1.0)
            score = 0.4 + 0.2 * (aspect_score * 0.5 + density_score * 0.5)
            score = round(min(max(score, 0.4), 0.6), 2)

            bbox = self._translate_bbox(
                float(cx), float(cy), float(cw), float(ch), image,
            )

            findings.append(
                Finding(
                    entity_type=EntityType.SIGNATURE,
                    original_text=None,
                    score=score,
                    page=image.page,
                    bbox=bbox,
                ),
            )

        return findings

    # ── Helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _decode_image(content: bytes) -> np.ndarray | None:
        """Decode raw image bytes into an OpenCV BGR matrix."""
        buf = np.frombuffer(content, dtype=np.uint8)
        mat = cv2.imdecode(buf, cv2.IMREAD_COLOR)
        return mat

    @staticmethod
    def _translate_bbox(
        x: float,
        y: float,
        w: float,
        h: float,
        image: ExtractedImage,
    ) -> BBox:
        """Translate image-local coordinates to page coordinates.

        If the ExtractedImage has a known bbox on the page, offsets are
        added so the finding bbox is in page-coordinate space.
        """
        if image.bbox is not None:
            ox, oy = image.bbox[0], image.bbox[1]
        else:
            ox, oy = 0.0, 0.0

        return BBox(
            x0=ox + x,
            y0=oy + y,
            x1=ox + x + w,
            y1=oy + y + h,
        )
