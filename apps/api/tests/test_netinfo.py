from prahari.live.netinfo import classify


def test_classify_scopes():
    assert classify("127.0.0.1")["klass"] == "loopback"
    assert classify("::1")["klass"] == "loopback"
    assert classify("10.0.0.9")["scope"] == "internal"
    assert classify("192.168.1.5")["klass"] == "private"
    assert classify("100.100.0.1")["klass"] == "cgnat"
    assert classify("203.0.113.9")["klass"] == "documentation"
    ext = classify("52.84.23.17")
    assert ext["klass"] == "public" and ext["scope"] == "external"
    assert classify("not-an-ip")["klass"] == "unknown"
