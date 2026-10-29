from apex.core import analyze_text, validate_scope, sha256_bytes

def test_hash_is_stable():
    assert sha256_bytes(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

def test_text_triage_extracts_indicators_without_network():
    result = analyze_text("Visit https://example.com and email a@b.com. 192.168.1.1")
    assert "https://example.com" in result["urls"]
    assert "a@b.com" in result["emails"]
    assert "192.168.1.1" in result["ip_addresses"]
    assert result["network_activity"] is False

def test_scope_exact_and_subdomain_match():
    assert validate_scope("https://lab.example.com/path", ["example.com"])["allowed"] is True
    assert validate_scope("evil-example.com", ["example.com"])["allowed"] is False

def test_invalid_ip_ignored():
    assert analyze_text("999.999.999.999")["ip_addresses"] == []
