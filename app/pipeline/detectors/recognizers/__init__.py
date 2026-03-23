from app.pipeline.detectors.recognizers.es_address import EsAddressRecognizer
from app.pipeline.detectors.recognizers.es_dob import EsDateOfBirthRecognizer
from app.pipeline.detectors.recognizers.es_iban import EsIbanRecognizer
from app.pipeline.detectors.recognizers.es_person import EsPersonRecognizer
from app.pipeline.detectors.recognizers.es_phone import EsPhoneRecognizer

__all__ = [
    "EsAddressRecognizer",
    "EsDateOfBirthRecognizer",
    "EsIbanRecognizer",
    "EsPersonRecognizer",
    "EsPhoneRecognizer",
]
