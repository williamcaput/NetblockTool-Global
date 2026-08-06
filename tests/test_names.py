from netblocktool.names import name_similarity, normalize_name


def test_normalize_company_suffixes() -> None:
    assert normalize_name("MUFG Bank, Ltd.") == "mufg"


def test_name_similarity() -> None:
    assert name_similarity("MUFG", "MUFG Bank Ltd") == 100
