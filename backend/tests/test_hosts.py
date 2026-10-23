from app.api.stats import _looks_like_hostname
from app.collectors.rdns import HostResolver


def test_looks_like_hostname():
    assert _looks_like_hostname("EDV-PC01")
    assert _looks_like_hostname("fileserver.firma.local")
    assert not _looks_like_hostname("10.50.10.1")
    assert not _looks_like_hostname("443")
    assert not _looks_like_hostname("zwei worte")


def test_resolver_observe_filters_and_dedupes():
    r = HostResolver()
    r.observe("10.50.10.21", "10.50.10.21", "8.8.8.8", "127.0.0.1", "kaputt", None)
    assert r.pending == {"10.50.10.21"}  # öffentlich/Loopback/ungültig ausgelassen, doppelt nur einmal
    r.pending.clear()
    r.next_due["10.50.10.22"] = float("inf")  # kürzlich nachgeschlagen
    r.observe("10.50.10.22")
    assert not r.pending
