"""Executable contract for the audit-log hash chain.

These tests are immutable: they are the acceptance criteria for the eight
stubs in ``audit/chain.py``.  Only the standard library and pytest are used,
the fixtures are deterministic, and every comparison is exact.

The test-side reference digest below is the canonical form documented in
``audit/chain.py``, so fixtures are built without calling the stubs; damaged
fixtures are produced by editing one field and leaving the stored digest
stale, exactly like a tampering attacker who does not know the keying rule.
"""

import hashlib
import json

from audit.chain import (
    append,
    chain_batch,
    detect_reorder,
    detect_truncation,
    entry_hash,
    timestamp_window,
    validate_chain,
    verify_chain,
)

PAYLOAD_FIELDS = ("seq", "ts", "actor", "action", "detail")
BASE_TS = 1_700_000_000
STEP = 30
MAX_GAP = 120


def ref_hash(prev_hash, entry):
    """Canonical digest used to build fixtures independently of the stubs."""
    body = {
        "prev_hash": prev_hash or "",
        "entry": {field: entry[field] for field in PAYLOAD_FIELDS},
    }
    blob = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def make_chain(length=4, base_ts=BASE_TS, step=STEP):
    """Build an intact chain ordered oldest to newest with sequence 1..n."""
    chain = []
    prev_hash = ""
    for index in range(length):
        entry = {
            "seq": index + 1,
            "ts": base_ts + index * step,
            "actor": "user%d" % index,
            "action": "read",
            "detail": "record-%d" % index,
        }
        entry["prev_hash"] = prev_hash
        entry["hash"] = ref_hash(prev_hash, entry)
        chain.append(entry)
        prev_hash = entry["hash"]
    return chain


def payload(index, **overrides):
    """Build an append payload for position ``index``."""
    entry = {
        "ts": BASE_TS + index * STEP,
        "actor": "user%d" % index,
        "action": "read",
        "detail": "record-%d" % index,
    }
    entry.update(overrides)
    return entry


def test_entry_hash_binds_previous_hash():
    entry = {
        "seq": 7,
        "ts": BASE_TS,
        "actor": "alice",
        "action": "delete",
        "detail": "record-7",
    }
    left = entry_hash("0" * 64, entry)
    right = entry_hash("1" * 64, entry)
    assert isinstance(left, str)
    assert len(left) == 64
    assert set(left) <= set("0123456789abcdef")
    assert left == entry_hash("0" * 64, entry)
    assert left != right
    assert entry_hash("", entry) != entry_hash("0" * 64, entry)


def test_entry_hash_rejects_field_transfer():
    base = {"seq": 3, "ts": BASE_TS, "actor": "a", "action": "bc", "detail": "x"}
    moved = {"seq": 3, "ts": BASE_TS, "actor": "ab", "action": "c", "detail": "x"}
    shifted = {"seq": 3, "ts": BASE_TS, "actor": "a", "action": "b", "detail": "cx"}
    digest = entry_hash("", base)
    assert digest != entry_hash("", moved)
    assert digest != entry_hash("", shifted)


def test_append_sequence_starts_at_one_and_links_previous():
    chain = []
    first = append(chain, payload(0))
    assert chain == []
    assert first[0]["seq"] == 1
    assert first[0]["prev_hash"] == ""
    assert len(first[0]["hash"]) == 64
    second = append(first, payload(1))
    assert len(second) == 2
    assert [record["seq"] for record in second] == [1, 2]
    assert second[1]["prev_hash"] == first[0]["hash"]
    assert second[1]["hash"] != first[0]["hash"]


def test_verify_chain_detects_spliced_previous_link():
    chain = make_chain(4)
    forged = {
        "seq": 3,
        "ts": BASE_TS + 2 * STEP,
        "actor": "mallory",
        "action": "delete",
        "detail": "record-2",
        "prev_hash": "f" * 64,
    }
    forged["hash"] = ref_hash(forged["prev_hash"], forged)
    chain[2] = forged
    result = verify_chain(chain)
    assert result["ok"] is False
    assert result["index"] == 2
    assert result["reason"] == "prev_hash"


def test_verify_chain_reports_first_break_only():
    chain = make_chain(5)
    chain[1]["seq"] = 9
    chain[3]["detail"] = "rewritten"
    chain[4]["actor"] = "mallory"
    result = verify_chain(chain)
    assert result["ok"] is False
    assert result["index"] == 1
    assert result["reason"] == "seq"


def test_detect_truncation_compares_expected_length():
    chain = make_chain(5)
    assert detect_truncation(chain, 5) is False
    assert detect_truncation(chain[:4], 5) is True
    assert detect_truncation(chain[:3], 5) is True
    assert detect_truncation(chain[:1], 5) is True
    assert detect_truncation([], 0) is False


def test_detect_reorder_catches_middle_swap():
    chain = make_chain(6)
    assert detect_reorder(chain) is False
    swapped = make_chain(6)
    swapped[2], swapped[3] = swapped[3], swapped[2]
    assert detect_reorder(swapped) is True
    numbered = make_chain(4)
    numbered[2]["seq"] = 9
    assert detect_reorder(numbered) is True


def test_timestamp_window_uses_adjacent_gap():
    chain = make_chain(5)
    assert timestamp_window(chain, MAX_GAP) == []
    spike = make_chain(5)
    spike[4]["ts"] = spike[3]["ts"] + 900
    assert timestamp_window(spike, MAX_GAP) == [4]
    backward = make_chain(5)
    backward[1]["ts"] = backward[0]["ts"] - 5
    assert timestamp_window(backward, MAX_GAP) == [1]


def test_validate_chain_rejects_truncated_hash():
    chain = make_chain(3)
    assert validate_chain(chain) == []
    truncated = make_chain(3)
    truncated[1]["hash"] = truncated[1]["hash"][:16]
    assert validate_chain(truncated) == ["index=1:hash:bad-length"]
    missing = make_chain(2)
    del missing[0]["actor"]
    assert validate_chain(missing) == ["index=0:missing:actor"]
    duplicate = make_chain(3)
    duplicate[2]["seq"] = 2
    assert validate_chain(duplicate) == [
        "index=1:seq:duplicate",
        "index=2:seq:duplicate",
    ]


def test_chain_batch_does_not_inherit_previous_chain():
    first = make_chain(4)
    second = make_chain(4)
    config = {"expected_len": 4, "max_gap": MAX_GAP}
    result = chain_batch([first, second], config)
    assert result["ok"] is True
    assert result["failed"] == []
    assert [item["ok"] for item in result["results"]] == [True, True]
    assert result["results"][1]["index"] is None
    assert result["results"][1]["reason"] == ""
    assert result["results"][1]["truncated"] is False
    assert result["results"][1]["bad_ts"] == []


def test_complete_chain_passes_all_checks():
    chain = make_chain(4)
    assert verify_chain(chain) == {"ok": True, "index": None, "reason": ""}
    assert detect_truncation(chain, 4) is False
    assert detect_reorder(chain) is False
    assert timestamp_window(chain, MAX_GAP) == []
    assert validate_chain(chain) == []
    built = []
    for index in range(4):
        built = append(built, payload(index))
    assert verify_chain(built) == {"ok": True, "index": None, "reason": ""}
    assert [record["hash"] for record in built] == [
        record["hash"] for record in chain
    ]


def test_deleted_middle_entry_detected_at_index():
    chain = make_chain(5)
    del chain[2]
    result = verify_chain(chain)
    assert result["ok"] is False
    assert result["index"] == 2
    assert result["reason"] == "seq"
    assert detect_truncation(chain, 5) is True


def test_modified_entry_content_detected():
    chain = make_chain(4)
    chain[2]["detail"] = "rewritten"
    result = verify_chain(chain)
    assert result["ok"] is False
    assert result["index"] == 2
    assert result["reason"] == "entry_hash"


def test_truncated_tail_detected():
    chain = make_chain(5)
    short = chain[:3]
    assert verify_chain(short) == {"ok": True, "index": None, "reason": ""}
    assert detect_truncation(short, 5) is True
    assert detect_truncation(chain, 5) is False
    assert detect_truncation(chain[:4], 5) is True


def single_result(chain, expected_len, max_gap):
    """Per-chain result computed from the individual checks."""
    report = verify_chain(chain)
    truncated = detect_truncation(chain, expected_len)
    bad_ts = timestamp_window(chain, max_gap)
    return {
        "ok": report["ok"] and not truncated and not bad_ts,
        "index": report["index"],
        "reason": report["reason"],
        "truncated": truncated,
        "bad_ts": bad_ts,
    }


def test_batch_results_match_single_chain_checks():
    config = {"expected_len": 4, "max_gap": MAX_GAP}
    intact = make_chain(4)
    damaged = make_chain(4)
    damaged[2]["detail"] = "rewritten"
    batch = chain_batch([intact, damaged], config)
    assert batch["ok"] is False
    assert batch["failed"] == [1]
    assert batch["results"] == [
        single_result(intact, 4, MAX_GAP),
        single_result(damaged, 4, MAX_GAP),
    ]
