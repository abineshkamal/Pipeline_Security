from app.config import normalize_db_url


def test_railway_style_postgres_urls_use_psycopg3():
    assert normalize_db_url("postgresql://u:p@host:5432/db") == "postgresql+psycopg://u:p@host:5432/db"
    assert normalize_db_url("postgres://u:p@host/db") == "postgresql+psycopg://u:p@host/db"


def test_explicit_driver_and_sqlite_untouched():
    assert normalize_db_url("postgresql+psycopg://u@h/db") == "postgresql+psycopg://u@h/db"
    assert normalize_db_url("sqlite:///x.db") == "sqlite:///x.db"
    assert normalize_db_url("") == ""
