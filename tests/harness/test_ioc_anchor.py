from ares.harness.ioc_anchor import scan_iocs, IOCMatch


def test_detects_credential_tooling():
    hits = scan_iocs("the host ran procdump -ma lsass.dmp")
    names = {h.ioc_name for h in hits}
    assert "credential_access" in names


def test_case_insensitive():
    assert scan_iocs("ProcDump and MIMIKATZ")  # non-empty


def test_benign_text_no_hits():
    assert scan_iocs("the user opened a spreadsheet") == ()


def test_match_carries_text():
    hits = scan_iocs("dumped ntds.dit")
    assert any(isinstance(h, IOCMatch) and "ntds.dit" in h.matched_text.lower() for h in hits)
