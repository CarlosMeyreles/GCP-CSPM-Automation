import pytest


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("GCP_PROJECT_ID", "test-proj")
    monkeypatch.setenv("BQ_DATASET", "test_ds")
