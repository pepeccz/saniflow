from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = {"env_prefix": "SANIFLOW_"}

    # File constraints
    MAX_FILE_SIZE: int = 20 * 1024 * 1024  # 20 MB
    SUPPORTED_FORMATS: list[str] = [
        "application/pdf",
        "image/jpeg",
        "image/png",
    ]

    # Sanitization defaults
    DEFAULT_LEVEL: str = "standard"

    # Confidence thresholds
    CONFIDENCE_THRESHOLD_REGEX: float = 0.7
    CONFIDENCE_THRESHOLD_NER: float = 0.5

    # OCR / NLP
    TESSERACT_LANG: str = "spa"
    SPACY_MODEL: str = "es_core_news_md"

    # Models
    YUNET_MODEL_PATH: str = "/app/models/face_detection_yunet_2023mar.onnx"

    # Temp storage
    TEMP_DIR: str = "/tmp/saniflow"


settings = Settings()
