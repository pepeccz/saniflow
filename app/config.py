from pydantic import field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = {"env_prefix": "SANIFLOW_"}

    @field_validator("API_KEYS", mode="before")
    @classmethod
    def _parse_api_keys(cls, v: object) -> list[str]:
        """Accept a comma-separated string and return a list of non-empty keys."""
        if isinstance(v, str):
            return [k.strip() for k in v.split(",") if k.strip()]
        if isinstance(v, list):
            return [str(k).strip() for k in v if str(k).strip()]
        return []

    # File constraints
    MAX_FILE_SIZE: int = 20 * 1024 * 1024  # 20 MB
    SUPPORTED_FORMATS: list[str] = [
        "application/pdf",
        "image/jpeg",
        "image/png",
        "image/tiff",
        "image/bmp",
        "image/webp",
        "text/plain",
        "text/markdown",
    ]

    # Sanitization defaults
    DEFAULT_LEVEL: str = "standard"
    DEFAULT_REDACTION_STYLE: str = "black"

    # Confidence thresholds
    CONFIDENCE_THRESHOLD_REGEX: float = 0.7
    CONFIDENCE_THRESHOLD_NER: float = 0.5

    # OCR / NLP
    TESSERACT_LANG: str = "spa"
    SPACY_MODEL: str = "es_core_news_md"

    # Models
    YUNET_MODEL_PATH: str = "/app/models/face_detection_yunet_2023mar.onnx"
    YUNET_SCORE_THRESHOLD: float = 0.4

    # Rate limiting
    RATE_LIMIT: int = 30  # requests per minute per client IP

    # Authentication
    API_KEYS: list[str] = []

    # Document region extraction
    DOCUMENT_EXTRACTION_ENABLED: bool = True
    DOCUMENT_MIN_AREA_RATIO: float = 0.10  # 10% of image area

    # Audit logging
    AUDIT_ENABLED: bool = True
    AUDIT_LOG_PATH: str = "audit.log"

    # GLiNER (optional deep PII detection)
    GLINER_ENABLED: bool = False
    GLINER_MODEL: str = "urchade/gliner_multi_pii-v1"
    GLINER_THRESHOLD: float = 0.5
    GLINER_LABELS: list[str] = [
        "person", "email", "phone number", "iban", "credit card number",
        "date of birth", "address", "passport number", "social security number",
        "driver license", "medical condition", "medication", "ip address",
        "bank account", "tax identification number", "vehicle registration",
    ]

    # Temp storage
    TEMP_DIR: str = "/tmp/saniflow"


settings = Settings()
