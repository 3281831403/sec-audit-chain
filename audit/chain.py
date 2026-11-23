"""Audit-log hash chaining: executable specification (stubs only).

The audit log is append-only.  Every record is bound to its predecessor by a
SHA-256 digest that covers both the full record and the predecessor hash, so
removing, reordering, truncating or rewriting a record must be detectable
without trusting the stored digests.  Sequence numbers start at one and grow
by exactly one.  All comparisons are exact: there is no tolerance anywhere
(tolerance 0), and nothing here is allowed to mutate its arguments.

Data shapes
-----------

An *entry* is a dict::

    {
        "seq": int,        # 1-based position, 1, 2, 3, ...
        "ts": int,         # Unix timestamp in seconds
        "actor": str,      # account that performed the action
        "action": str,     # verb, for example create, read, delete
        "detail": str,     # free-form but hashed detail
        "prev_hash": str,  # previous entry hash, "" for the genesis entry
        "hash": str,       # 64 lowercase hex chars, this entry's digest
    }

The first five fields make up the *payload* of an entry; ``prev_hash`` and
``hash`` are the chaining metadata.  A payload handed to :func:`append` is a
dict that contains at least ``ts``, ``actor``, ``action`` and ``detail``; any
``seq``, ``prev_hash`` or ``hash`` key in it is ignored and recomputed.

Canonical digest
----------------

``entry_hash(prev_hash, entry)`` is the lowercase SHA-256 hex digest of the
UTF-8 encoding of::

    json.dumps(
        {
            "prev_hash": prev_hash,
            "entry": {
                "seq": entry["seq"],
                "ts": entry["ts"],
                "actor": entry["actor"],
                "action": entry["action"],
                "detail": entry["detail"],
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    )

Thus the digest covers the predecessor hash and every payload field, and the
JSON separators keep field boundaries unambiguous: moving characters from one
field into the next changes the digest.  Only the five payload fields are
hashed; other keys of ``entry`` are ignored.

Tolerance is zero: no whitespace trimming, no case folding of strings, no
rounding of timestamps, and no allowance for a gap or a sequence number that
is off by one.  Every function is deterministic and standard-library only.
"""

import hashlib
import json

PAYLOAD_FIELDS = ("seq", "ts", "actor", "action", "detail")
APPEND_PAYLOAD_FIELDS = ("ts", "actor", "action", "detail")
REQUIRED_FIELDS = PAYLOAD_FIELDS + ("prev_hash", "hash")
HASH_HEX_LEN = 64
FIRST_SEQ = 1


def entry_hash(prev_hash, entry):
    """Return the lowercase SHA-256 hex digest that binds an entry to its predecessor.

    ``prev_hash`` is the predecessor digest, or ``""`` (``None`` is treated as
    empty) for the genesis entry.  ``entry`` is a dict; its payload fields
    ``seq``, ``ts``, ``actor``, ``action`` and ``detail`` are hashed together
    with ``prev_hash`` using the canonical form documented in the module
    docstring.  Any other key of ``entry``, including ``prev_hash`` and
    ``hash``, is ignored.

    The result is exactly 64 lowercase hex characters.  The digest must
    depend on ``prev_hash``: two calls with the same payload but different
    predecessors must return different digests, otherwise the chain degrades
    into a bag of independent hashes and a spliced predecessor goes unnoticed.
    The input structure must also be unambiguous: two payloads that differ
    only by moving characters across a field boundary, for example actor
    ``a`` plus action ``bc`` versus actor ``ab`` plus action ``c``, must not
    collide.

    Raises ``ValueError`` when ``entry`` is not a dict or a payload field is
    missing.  This function never reads or writes a ``hash`` field.
    """
    if not isinstance(entry, dict):
        raise ValueError("entry must be a dict")
    for field in PAYLOAD_FIELDS:
        if field not in entry:
            raise ValueError("entry is missing payload field %r" % (field,))
    body = {
        "prev_hash": "" if prev_hash is None else prev_hash,
        "entry": {field: entry[field] for field in PAYLOAD_FIELDS},
    }
    blob = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def append(chain, entry):
    """Return a new chain with ``entry`` appended at the end.

    ``chain`` is a list of entries ordered oldest to newest and is not
    modified.  ``entry`` is a payload dict; the appended record is a new dict
    holding exactly the five payload fields plus ``prev_hash`` and ``hash``.

    The new record is numbered ``len(chain) + 1``, so the first record of an
    empty chain gets sequence number one, not zero.  Its ``prev_hash`` is
    ``""`` for the genesis record and the last record's ``hash`` otherwise,
    and its ``hash`` is ``entry_hash(prev_hash, new_record)``.  A ``seq``,
    ``prev_hash`` or ``hash`` supplied by the caller must be overwritten, not
    trusted: an attacker who controls the payload must not be able to choose
    its position or its link.

    Raises ``ValueError`` when ``chain`` is not a list, when a chain element
    is not a dict, when the last element has no usable ``hash``, or when
    ``entry`` is missing a payload field.  The returned list shares no
    mutable state with ``chain``.
    """
    if not isinstance(chain, list):
        raise ValueError("chain must be a list")
    for record in chain:
        if not isinstance(record, dict):
            raise ValueError("every chain element must be a dict")
    if not isinstance(entry, dict):
        raise ValueError("entry must be a dict")
    for field in APPEND_PAYLOAD_FIELDS:
        if field not in entry:
            raise ValueError("entry is missing payload field %r" % (field,))

    if chain:
        last_hash = chain[-1].get("hash")
        if not isinstance(last_hash, str) or not last_hash:
            raise ValueError("last element has no usable hash")
        seq = len(chain) + FIRST_SEQ
        prev_hash = last_hash
    else:
        seq = FIRST_SEQ
        prev_hash = ""

    record = {
        "seq": seq,
        "ts": entry["ts"],
        "actor": entry["actor"],
        "action": entry["action"],
        "detail": entry["detail"],
        "prev_hash": prev_hash,
    }
    record["hash"] = entry_hash(prev_hash, record)

    # Copy the elements as well as the list so later mutation of either the
    # old chain or the returned one cannot affect the other.
    new_chain = [dict(existing) for existing in chain]
    new_chain.append(record)
    return new_chain


def verify_chain(chain):
    """Verify every link of a chain ordered oldest to newest.

    Walk the records in ascending order and stop at the first broken one,
    because later records sit behind that break and a report about the last
    break would hide where the damage starts.  The result is::

        {
            "ok": bool,          # True only when no record is broken
            "index": int | None,  # 0-based index of the first broken record
            "reason": str,        # "" when ok, else one of the codes below
        }

    Reasons, checked in this order for each record:

      * ``"shape"``: the element is not a dict, or a required field is
        missing;
      * ``"seq"``: ``record["seq"]`` is not ``index + 1``;
      * ``"prev_hash"``: for index 0 ``record["prev_hash"]`` is not ``""``,
        and for index i it does not equal ``chain[i - 1]["hash"]`` exactly;
      * ``"entry_hash"``: ``record["hash"]`` does not equal
        ``entry_hash(record["prev_hash"], record)``.

    Checking only the stored ``hash`` of each record is not enough: a spliced
    record can carry a self-consistent digest while its ``prev_hash`` no
    longer names its predecessor, and only the link check catches that.  An
    empty chain is intact and returns ``{"ok": True, "index": None,
    "reason": ""}``.  The argument is never modified, and ordinary damage is
    reported in the dict instead of raising.
    """
    if not isinstance(chain, list):
        raise ValueError("chain must be a list")

    for index, record in enumerate(chain):
        if not isinstance(record, dict):
            return {"ok": False, "index": index, "reason": "shape"}
        for field in REQUIRED_FIELDS:
            if field not in record:
                return {"ok": False, "index": index, "reason": "shape"}
        if record["seq"] != index + FIRST_SEQ:
            return {"ok": False, "index": index, "reason": "seq"}
        expected_prev = "" if index == 0 else chain[index - 1]["hash"]
        if record["prev_hash"] != expected_prev:
            return {"ok": False, "index": index, "reason": "prev_hash"}
        try:
            expected_hash = entry_hash(record["prev_hash"], record)
        except (TypeError, ValueError):
            return {"ok": False, "index": index, "reason": "entry_hash"}
        if record["hash"] != expected_hash:
            return {"ok": False, "index": index, "reason": "entry_hash"}

    return {"ok": True, "index": None, "reason": ""}


def detect_truncation(chain, expected_len):
    """Return ``True`` when the tail of a chain is missing or shortened.

    ``expected_len`` is the number of records the log must contain, taken
    from an independent source such as a signed record count; it is an int,
    ``bool`` is rejected, and negative values raise ``ValueError``.

    A chain is truncated when ``len(chain) != expected_len``, or when the
    chain is non-empty and its last ``seq`` is not ``expected_len``.  The
    second rule catches a tail that was replaced by records with lower
    numbers, which keeps the length unchanged.  Comparing the length with
    itself, or with the number of records actually present, can never be true
    and would report every attack as intact.  An empty chain is truncated
    exactly when ``expected_len`` is not zero.

    Malformed records raise ``ValueError`` for missing or non-integer
    ``seq``.  The argument is not modified.
    """
    if (
        not isinstance(expected_len, int)
        or isinstance(expected_len, bool)
        or expected_len < 0
    ):
        raise ValueError("expected_len must be a non-negative int")
    if not isinstance(chain, list):
        raise ValueError("chain must be a list")

    last_seq = None
    if chain:
        last = chain[-1]
        if not isinstance(last, dict):
            raise ValueError("last element is not a dict")
        if (
            "seq" not in last
            or not isinstance(last["seq"], int)
            or isinstance(last["seq"], bool)
        ):
            raise ValueError("last element has no integer seq")
        last_seq = last["seq"]

    if len(chain) != expected_len:
        return True
    if chain and last_seq != expected_len:
        return True
    return False


def detect_reorder(chain):
    """Return ``True`` when sequence numbers are out of order.

    The sequence numbers of an intact chain are exactly ``1, 2, ..., n`` in
    that order.  Return ``True`` as soon as any position holds the wrong
    number, including a swap in the middle of the chain that leaves the first
    and last numbers untouched; comparing only the endpoints misses exactly
    that attack.  Duplicate or missing numbers also count as reordering.

    Non-dict elements or missing/non-integer ``seq`` values make the chain
    reordered and return ``True``.  The argument is not modified.
    """
    if not isinstance(chain, list):
        raise ValueError("chain must be a list")

    for index, record in enumerate(chain):
        if not isinstance(record, dict):
            return True
        if "seq" not in record:
            return True
        seq = record["seq"]
        if not isinstance(seq, int) or isinstance(seq, bool):
            return True
        if seq != index + FIRST_SEQ:
            return True
    return False


def timestamp_window(chain, max_gap):
    """Return the indices whose gap from the previous record is abnormal.

    ``max_gap`` is the largest allowed difference between consecutive
    timestamps in seconds, as an int (``bool`` rejected) that is not negative;
    a non-conforming value raises ``ValueError``.  For every index i from 1 to
    ``len(chain) - 1`` compute ``delta = chain[i]["ts"] - chain[i - 1]["ts"]``
    and report i when ``delta > max_gap`` or ``delta < 0``.  The indices are
    returned in ascending order; an intact chain returns ``[]``.

    The check is on the adjacent difference, not on the absolute timestamp: a
    log that starts at any epoch value is fine, and comparing the timestamp
    itself with the threshold would flag every record of a healthy log and
    stop meaning anything.

    Malformed records, or a missing/non-integer ``ts``, raise ``ValueError``.
    The argument is not modified.
    """
    if (
        not isinstance(max_gap, int)
        or isinstance(max_gap, bool)
        or max_gap < 0
    ):
        raise ValueError("max_gap must be a non-negative int")
    if not isinstance(chain, list):
        raise ValueError("chain must be a list")

    bad_indices = []
    previous_ts = None
    for index, record in enumerate(chain):
        if not isinstance(record, dict):
            raise ValueError("element %d is not a dict" % (index,))
        if "ts" not in record:
            raise ValueError("element %d has no ts" % (index,))
        ts = record["ts"]
        if not isinstance(ts, int) or isinstance(ts, bool):
            raise ValueError("element %d has a non-integer ts" % (index,))
        if index > 0:
            delta = ts - previous_ts
            if delta > max_gap or delta < 0:
                bad_indices.append(index)
        previous_ts = ts
    return bad_indices


def validate_chain(chain):
    """Return a list of structural problem codes; ``[]`` exactly when intact.

    This function checks structure only: it does not recompute digests and
    does not judge whether the log is complete.  For each record, in ascending
    index order, append applicable codes:

      * ``"index=<i>:entry:not-dict"`` when the element is not a dict;
      * ``"index=<i>:missing:<field>"`` for each missing required field, in
        the order seq, ts, actor, action, detail, prev_hash, hash;
      * ``"index=<i>:hash:bad-length"`` and
        ``"index=<i>:prev_hash:bad-length"`` when the value is not a string of
        exactly 64 characters, and the matching ``"<field>:not-hex"`` when a
        64-character value is not lowercase hexadecimal.  The empty string is
        a valid ``prev_hash`` only at index 0, where it marks the genesis
        record;
      * ``"index=<i>:seq:duplicate"`` for every occurrence of a sequence
        number that appears more than once in the chain.

    A truncated digest, for example one cut to 16 characters, is invalid and
    must be reported: checking only that the characters look hexadecimal lets
    a shortened hash pass and weakens the binding.  Records that are not
    dicts contribute only their first code.  The argument is not modified.
    """
    if not isinstance(chain, list):
        raise ValueError("chain must be a list")

    seq_values = [
        record["seq"]
        for record in chain
        if isinstance(record, dict) and "seq" in record
    ]

    problems = []
    hex_digits = set("0123456789abcdef")
    for index, record in enumerate(chain):
        prefix = "index=%d:" % (index,)
        if not isinstance(record, dict):
            problems.append(prefix + "entry:not-dict")
            continue
        for field in REQUIRED_FIELDS:
            if field not in record:
                problems.append(prefix + "missing:" + field)
        for field in ("hash", "prev_hash"):
            if field not in record:
                continue
            value = record[field]
            if (
                field == "prev_hash"
                and index == 0
                and isinstance(value, str)
                and value == ""
            ):
                continue
            if not isinstance(value, str) or len(value) != HASH_HEX_LEN:
                problems.append(prefix + field + ":bad-length")
            elif not set(value) <= hex_digits:
                problems.append(prefix + field + ":not-hex")
        if "seq" in record:
            seq = record["seq"]
            if seq_values.count(seq) > 1:
                problems.append(prefix + "seq:duplicate")
    return problems


def chain_batch(chains, config):
    """Validate several independent chains and report per-chain results.

    ``chains`` is a list of chains and ``config`` is
    ``{"expected_len": int, "max_gap": int}``, both ints (``bool`` rejected)
    that are not negative; a malformed config raises ``ValueError``.

    Each chain yields one result dict::

        {
            "ok": bool,          # chain_ok and not truncated and no bad_ts
            "index": int | None,  # verify_chain index
            "reason": str,        # verify_chain reason
            "truncated": bool,    # detect_truncation(chain, expected_len)
            "bad_ts": [int],      # timestamp_window(chain, max_gap)
        }

    computed with :func:`verify_chain`, :func:`detect_truncation` and
    :func:`timestamp_window`.  Return::

        {
            "ok": bool,           # every result is ok
            "results": [result],  # input order
            "failed": [int],      # indices whose result is not ok
        }

    The chains are independent: no ``prev_hash``, sequence number, timestamp,
    digest or error from one chain may leak into the next one.  Carrying the
    previous chain's tail hash into the following chain makes every chain
    after the first look spliced, and it also makes a batched result differ
    from validating the chains one at a time.  A chain's own result must
    equal the result of checking that chain alone.
    """
    if not isinstance(config, dict):
        raise ValueError("config must be a dict")
    for key in ("expected_len", "max_gap"):
        if key not in config:
            raise ValueError("config is missing %r" % (key,))
        value = config[key]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError("config[%r] must be a non-negative int" % (key,))
    if not isinstance(chains, list):
        raise ValueError("chains must be a list")

    expected_len = config["expected_len"]
    max_gap = config["max_gap"]

    results = []
    for chain in chains:
        # Each chain is an independent log: all state is recomputed from the
        # chain itself, so nothing carries over from the previous iteration.
        report = verify_chain(chain)
        truncated = detect_truncation(chain, expected_len)
        bad_ts = timestamp_window(chain, max_gap)
        results.append(
            {
                "ok": report["ok"] and not truncated and not bad_ts,
                "index": report["index"],
                "reason": report["reason"],
                "truncated": truncated,
                "bad_ts": bad_ts,
            }
        )

    failed = [index for index, result in enumerate(results) if not result["ok"]]
    return {
        "ok": not failed,
        "results": results,
        "failed": failed,
    }
