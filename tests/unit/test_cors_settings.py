from __future__ import annotations

from app.core.config import Settings


def test_cors_production_is_explicit_only() -> None:
    settings = Settings(
        env="production",
        web_origin="https://blueteam-os.vercel.app",
        cors_origins="https://blueteam-os.vercel.app,https://preview.example",
        cors_origin_regex="",
    )
    origins = settings.cors_allow_origins()
    assert "https://blueteam-os.vercel.app" in origins
    assert "https://preview.example" in origins
    assert "http://localhost:3000" not in origins
    assert settings.cors_allow_origin_regex() is None


def test_cors_dev_allows_localhost_and_optional_vercel_regex() -> None:
    settings = Settings(env="development", web_origin="http://127.0.0.1:3000", cors_origins="", cors_origin_regex="")
    origins = settings.cors_allow_origins()
    assert "http://127.0.0.1:3000" in origins
    assert "http://localhost:3000" in origins
    assert settings.cors_allow_origin_regex() == r"https://.*\.vercel\.app"
