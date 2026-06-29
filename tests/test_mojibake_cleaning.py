from advisoryops.mojibake import clean_mojibake_value

def _assert_clean(s: str) -> None:
    assert "???" not in s
    assert "??" not in s  # should not leave any ??-prefixed sequences
    assert "?" not in s

def test_clean_scalar() -> None:
    raw = "CareFusion???s device said ???hello??? ? and more"
    cleaned = clean_mojibake_value(raw)
    assert isinstance(cleaned, str)
    _assert_clean(cleaned)

def test_clean_list() -> None:
    raw = ["CareFusion???s", "? spaced", "???quoted???"]
    cleaned = clean_mojibake_value(raw)
    assert isinstance(cleaned, list)
    for item in cleaned:
        assert isinstance(item, str)
        _assert_clean(item)
