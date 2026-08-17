from assurance_hub.discovery import classify_column, normalized_identifier


def test_identifier_normalization_handles_insurance_column_styles() -> None:
    assert normalized_identifier("CLIENT_FULL_NAME") == "client_full_name"
    assert normalized_identifier("PaidAmount") == "paid_amount"


def test_classification_is_metadata_only_and_deterministic() -> None:
    assert classify_column("IS_AADHAAR_ATTACHED") == ("restricted", 98)
    assert classify_column("PayeeName") == ("confidential", 92)
    assert classify_column("PaymentModeName") == ("internal", 84)
    assert classify_column("UpdateNum") is None
