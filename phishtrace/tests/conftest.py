from __future__ import annotations

from pathlib import Path

import pytest

from phishtrace.config import AuthConfig, Config, FetcherConfig, LimitsConfig, ProviderSettings
from phishtrace.storage.db import init_db
from phishtrace.storage.evidence import EvidenceStore
from phishtrace.storage.repository import Repository


def make_config(tmp_path: Path, **overrides) -> Config:
    data = {
        "host": "127.0.0.1",
        "port": 8088,
        "data_dir": tmp_path / "data",
        "auth": AuthConfig(enabled=False),
        "limits": LimitsConfig(max_retries=1, retry_backoff_seconds=0.01, provider_timeout_seconds=5),
        "fetcher": FetcherConfig(allow_localhost=True),
        "providers": {},
        "env": {},
    }
    data.update(overrides)
    config = Config(**data)
    config.data_dir.mkdir(parents=True, exist_ok=True)
    return config


@pytest.fixture()
def tmp_config(tmp_path) -> Config:
    return make_config(tmp_path)


@pytest.fixture()
def repo(tmp_config) -> Repository:
    engine, factory = init_db(tmp_config.sqlalchemy_url, tmp_config.data_dir)
    return Repository(factory, EvidenceStore(tmp_config.evidence_dir))


@pytest.fixture()
def provider_settings():
    return ProviderSettings()
