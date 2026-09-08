"""Deployment configuration. Secrets are read from files where possible."""
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse, quote


def secret(name: str, default: str = "") -> str:
    path = os.getenv(name + "_FILE")
    return Path(path).read_text().strip() if path else os.getenv(name, default)


@dataclass
class Settings:
    database_url: str
    public_url: str = "http://127.0.0.1:8090/mcp"
    issuer: str = ""
    jwks_url: str = ""
    subjects: dict[str, str] = field(default_factory=dict)
    allowed_hosts: list[str] = field(default_factory=lambda: ["127.0.0.1:*", "localhost:*"])
    allowed_origins: list[str] = field(default_factory=list)
    requests_per_minute: int = 300
    management_key: str = ""

    def __post_init__(self):
        url = urlparse(self.public_url)
        if url.scheme not in {"http", "https"} or not url.hostname or url.query or url.fragment:
            raise ValueError("PUBLIC_URL must be an absolute HTTP(S) MCP endpoint")
        if url.scheme != "https" and url.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("Non-loopback PUBLIC_URL requires HTTPS")
        if bool(self.issuer) != bool(self.jwks_url):
            raise ValueError("OIDC_ISSUER and OIDC_JWKS_URL must be configured together")
        if self.issuer:
            for value in (self.issuer, self.jwks_url):
                if urlparse(value).scheme != "https":
                    raise ValueError("OIDC endpoints require HTTPS")
        if not 1 <= self.requests_per_minute <= 100000:
            raise ValueError("REQUESTS_PER_MINUTE must be between 1 and 100000")
        if not isinstance(self.subjects, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in self.subjects.items()
        ):
            raise ValueError("OIDC_SUBJECTS must map subjects to provisioned principal IDs")

    @classmethod
    def from_env(cls):
        database = secret("DATABASE_URL")
        if not database:
            password = secret("DB_PASSWORD")
            if not password:
                raise ValueError("Set DATABASE_URL or DB_PASSWORD_FILE")
            database = (
                "postgresql+psycopg://distributedai:"
                + quote(password, safe="")
                + "@" + os.getenv("DB_HOST", "db") + ":5432/distributedai"
            )
        public = os.getenv("PUBLIC_URL", "http://127.0.0.1:8090/mcp")
        host = urlparse(public).netloc
        return cls(
            database_url=database,
            public_url=public,
            issuer=os.getenv("OIDC_ISSUER", ""),
            jwks_url=os.getenv("OIDC_JWKS_URL", ""),
            subjects=json.loads(secret("OIDC_SUBJECTS", "{}")),
            allowed_hosts=os.getenv("ALLOWED_HOSTS", f"{host},127.0.0.1:*,localhost:*").split(","),
            allowed_origins=[v for v in os.getenv("ALLOWED_ORIGINS", "").split(",") if v],
            requests_per_minute=int(os.getenv("REQUESTS_PER_MINUTE", "300")),
            management_key=secret("MANAGEMENT_KEY"),
        )
