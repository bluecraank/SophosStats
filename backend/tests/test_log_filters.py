import pytest
from pydantic import ValidationError
from sqlalchemy.dialects import postgresql

from app.services.log_filters import LogFilter, to_condition


def sql(field, op, value=""):
    expr = to_condition(LogFilter(field=field, op=op, value=value))
    # literal_binds verdoppelt % (pyformat-Paramstil) – für die Prüfung zurücknehmen
    return str(expr.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True})).replace("%%", "%")


def test_text_operators():
    assert "ILIKE '%admin%'" in sql("user_name", "contains", "admin")
    assert "NOT" in sql("user_name", "not_contains", "svc_") and "IS NULL" in sql("user_name", "not_contains", "svc_")
    assert "ILIKE 'TCP'" in sql("protocol", "eq", "TCP")
    # Platzhalterzeichen im Wert werden escaped
    assert "ILIKE '%50\\%%'" in sql("message", "contains", "50%")


def test_numeric_columns():
    assert "log_entries.dst_port = 443" in sql("dst_port", "eq", "443")
    assert "log_entries.sent_bytes > 1000000" in sql("sent_bytes", "gt", "1000000")


def test_cidr_on_ip_column():
    s = sql("src_ip", "cidr", "10.10.0.0/16")
    assert "<<=" in s and "10.10.0.0/16" in s and "CASE WHEN" in s


def test_raw_json_field():
    assert "log_entries.fields ->> 'app_name'" in sql("app_name", "eq", "Teams")
    # Rohfeld numerisch vergleichen: nur numerische Werte werden gecastet
    assert "CAST((log_entries.fields ->> 'con_duration') AS BIGINT)" in sql("con_duration", "gt", "60")


def test_exists_missing():
    assert "IS NOT NULL" in sql("user_name", "exists")
    assert "IS NULL" in sql("app_name", "missing")


@pytest.mark.parametrize(
    "field,op,value",
    [("src_ip", "cidr", "kein-netz"), ("dst_port", "gt", "abc"), ("user_name", "gt", "5")],
)
def test_invalid_values(field, op, value):
    with pytest.raises(ValueError):
        to_condition(LogFilter(field=field, op=op, value=value))


def test_invalid_field_name_rejected():
    with pytest.raises(ValidationError):
        LogFilter(field="x; DROP TABLE users", op="eq", value="1")
    with pytest.raises(ValidationError):
        LogFilter(field="src_ip", op="like", value="1")


def test_host_ip_matches_source_or_destination():
    s = sql("host_ip", "eq", "10.50.10.21")
    assert "log_entries.src_ip ILIKE '10.50.10.21'" in s and " OR " in s and "dst_ip" in s
    # ausschließen: weder Quelle noch Ziel
    n = sql("host_ip", "ne", "10.50.10.21")
    assert " AND " in n and "NOT" in n
