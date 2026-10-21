from types import SimpleNamespace

from app.api.compliance import _actor

MSG = "Firewall Rule 'Web' was modified by 'admin' from '10.0.0.5' using 'GUI'"


def log(**kw):
    return SimpleNamespace(
        **({"time": 1, "user_name": None, "src_ip": None, "log_component": "GUI", "message": MSG} | kw)
    )


def test_actor_parsed_from_message():
    a = _actor(log(), True)
    assert (a["user"], a["src_ip"], a["via"], a["exact"]) == ("admin", "10.0.0.5", "GUI", True)


def test_actor_prefers_log_fields():
    a = _actor(log(user_name="nils", src_ip="10.9.9.9"), False)
    assert (a["user"], a["src_ip"], a["exact"]) == ("nils", "10.9.9.9", False)
