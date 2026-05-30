import time

import pytest

from aegis import ImmutableStore, TombstoneError


def test_append_creates_monotonic_versions():
    with ImmutableStore() as s:
        v1 = s.append("docs", "readme", {"text": "hello"}, author="agent-a")
        v2 = s.append("docs", "readme", {"text": "hello world"}, author="agent-b")
        assert v1.version == 1
        assert v2.version == 2
        assert s.read("docs", "readme").value == {"text": "hello world"}


def test_never_overwrites_history():
    with ImmutableStore() as s:
        s.append("docs", "k", {"n": 1}, author="a")
        s.append("docs", "k", {"n": 2}, author="a")
        s.append("docs", "k", {"n": 3}, author="a")
        hist = s.history("docs", "k")
        assert [h.value["n"] for h in hist] == [1, 2, 3]


def test_time_travel_by_version():
    with ImmutableStore() as s:
        s.append("docs", "k", {"n": 1}, author="a")
        s.append("docs", "k", {"n": 2}, author="a")
        assert s.read("docs", "k", as_of_version=1).value == {"n": 1}


def test_time_travel_by_timestamp():
    with ImmutableStore() as s:
        s.append("docs", "k", {"n": 1}, author="a")
        cutoff = time.time()
        time.sleep(0.01)
        s.append("docs", "k", {"n": 2}, author="a")
        assert s.read("docs", "k", as_of_ts=cutoff).value == {"n": 1}


def test_tombstone_is_logical_delete():
    with ImmutableStore() as s:
        s.append("docs", "k", {"n": 1}, author="a")
        s.tombstone("docs", "k", author="a")
        # latest view reports deleted
        with pytest.raises(TombstoneError):
            s.read("docs", "k")
        # but history is preserved
        assert s.read("docs", "k", as_of_version=1).value == {"n": 1}
        assert len(s.history("docs", "k")) == 2


def test_keys_excludes_tombstoned_by_default():
    with ImmutableStore() as s:
        s.append("docs", "live", {"x": 1}, author="a")
        s.append("docs", "dead", {"x": 1}, author="a")
        s.tombstone("docs", "dead", author="a")
        assert s.keys("docs") == ["live"]
        assert s.keys("docs", include_deleted=True) == ["dead", "live"]


def test_missing_key_raises():
    with ImmutableStore() as s:
        with pytest.raises(KeyError):
            s.read("docs", "nope")


def test_content_hash_stable_across_key_order():
    from aegis import content_hash

    assert content_hash({"a": 1, "b": 2}) == content_hash({"b": 2, "a": 1})


def test_provenance_recorded():
    with ImmutableStore() as s:
        v = s.append("docs", "k", {"n": 1}, author="agent-x")
        assert v.author == "agent-x"
        assert s.read("docs", "k").author == "agent-x"
