import pytest

import splunk_mcp
from splunk_mcp import check_index_scope, index_allowed


@pytest.fixture
def allowlist(monkeypatch):
    monkeypatch.setattr(splunk_mcp, "ALLOWED_INDEXES", {"production_cas_logsaps", "dig_cas_prod"})


@pytest.mark.parametrize("query", [
    "search index=production_cas_logsaps error",
    'search index="production_cas_logsaps" | head 1',
    "| tstats count where index=dig_cas_prod by sourcetype",
    "search index IN (production_cas_logsaps, dig_cas_prod) timeout",
    "search INDEX=Production_CAS_Logsaps",
])
def test_allowed_queries_pass(allowlist, query):
    check_index_scope(query)


@pytest.mark.parametrize("query,needle", [
    ("search index=production_ns_ngs tag_service", "production_ns_ngs"),
    ("search index=production_cas_logsaps OR index=production_ns_ngs", "production_ns_ngs"),
    ("search index=* error", "*"),
    ("search index=prod* error", "prod*"),
    ("search index IN (dig_cas_prod, main)", "main"),
    ("search error timeout", "Name one of them"),
    ("search index!=dig_cas_prod", "index!="),
])
def test_out_of_scope_queries_rejected(allowlist, query, needle):
    with pytest.raises(ValueError) as e:
        check_index_scope(query)
    assert needle in str(e.value)


def test_no_allowlist_means_no_restriction(monkeypatch):
    monkeypatch.setattr(splunk_mcp, "ALLOWED_INDEXES", set())
    check_index_scope("search index=* error")
    check_index_scope("search error")
    assert index_allowed("anything")


def test_index_allowed(allowlist):
    assert index_allowed("DIG_CAS_PROD")
    assert not index_allowed("production_ns_ngs")


@pytest.mark.asyncio
async def test_search_retries_session_errors(monkeypatch):
    monkeypatch.setattr(splunk_mcp, "ALLOWED_INDEXES", set())
    calls = []

    def fake_run(*args):
        calls.append(1)
        if len(calls) < 3:
            raise Exception("Request failed: Session is not logged in.")
        return [{"ok": 1}]

    monkeypatch.setattr(splunk_mcp, "_run_search", fake_run)
    assert await splunk_mcp.search_splunk("search index=main") == [{"ok": 1}]
    assert len(calls) == 3


@pytest.mark.asyncio
async def test_search_does_not_retry_other_errors(monkeypatch):
    monkeypatch.setattr(splunk_mcp, "ALLOWED_INDEXES", set())
    calls = []

    def fake_run(*args):
        calls.append(1)
        raise Exception("HTTP 400 Bad Request")

    monkeypatch.setattr(splunk_mcp, "_run_search", fake_run)
    with pytest.raises(Exception):
        await splunk_mcp.search_splunk("search index=main")
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_search_rejects_out_of_scope_before_connecting(allowlist, monkeypatch):
    def boom(*args):
        raise AssertionError("must not reach Splunk")

    monkeypatch.setattr(splunk_mcp, "_run_search", boom)
    with pytest.raises(ValueError):
        await splunk_mcp.search_splunk("index=production_ns_ngs")
