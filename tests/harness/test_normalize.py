from ares.harness.normalize import normalize


def test_strips_zero_width():
    assert normalize("ig​nore previous") == "ignore previous"


def test_folds_cyrillic_homoglyph():
    # Cyrillic 'ѕ' (U+0455) -> ASCII 's'
    assert normalize("ѕystem") == "system"


def test_nfkc_folds_fullwidth():
    assert normalize("ＳＹＳＴＥＭ") == "SYSTEM"


def test_collapses_spaces_but_keeps_newlines():
    assert normalize("a    b\n\nc") == "a b\n\nc"


def test_idempotent():
    once = normalize("ig​nore  previous")
    assert normalize(once) == once
