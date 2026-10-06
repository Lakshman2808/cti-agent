from cti_agent import iocs


def test_refang_variants():
    assert iocs.refang("hxxps://evil[.]com/a") == "https://evil.com/a"
    assert iocs.refang("bad(.)org") == "bad.org"
    assert iocs.refang("user[at]mail[dot]ru") == "user@mail.ru"
    assert iocs.refang("1.2.3[.]4") == "1.2.3.4"


def test_classify():
    assert iocs.classify("8.8.8.8") == "ipv4"
    assert iocs.classify("2001:4860:4860::8888") == "ipv6"
    assert iocs.classify("evil[.]com") == "domain"
    assert iocs.classify("hxxp://evil.com/x") == "url"
    assert iocs.classify("44d88612fea8a8f36de82e1278abb02f") == "md5"
    assert iocs.classify("3395856ce81f2b7382dee72602f798b642f14140") == "sha1"
    assert iocs.classify("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f") == "sha256"
    assert iocs.classify("cve-2021-44228") == "cve"
    assert iocs.classify("payload.exe") is None
    assert iocs.classify("hello world") is None


def test_extract_dedupes_and_skips_noise():
    text = """
    C2 at 45.9.148[.]10 and 45.9.148.10, plus internal 10.0.0.5.
    Dropper invoice.pdf.exe fetched hxxp://bad-domain[.]net/a.php?id=1.
    SHA256 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
    Uses T1566.001 and CVE-2023-4966. Contact ops[at]bad-domain[.]net.
    """
    r = iocs.extract(text)
    assert r.iocs["ipv4"] == ["45.9.148.10"]
    assert "10.0.0.5" in r.notes
    assert r.iocs["url"] == ["http://bad-domain.net/a.php?id=1"]
    assert r.iocs["domain"] == ["bad-domain.net"]
    assert r.iocs["email"] == ["ops@bad-domain.net"]
    assert r.iocs["cve"] == ["CVE-2023-4966"]
    assert r.iocs["attack_technique"] == ["T1566.001"]
    assert "md5" not in r.iocs  # no false md5 from inside the sha256
    assert "invoice.pdf.exe" not in str(r.iocs)


def test_extract_ipv6():
    r = iocs.extract("beacon to 2a01:4f8:c17:abcd::1 at 12:30:00")
    assert r.iocs.get("ipv6") == ["2a01:4f8:c17:abcd::1"]


def test_defang():
    assert iocs.defang("https://evil.com/x") == "hxxps[://]evil[.]com/x"
    assert iocs.defang("1.2.3.4") == "1[.]2[.]3[.]4"
