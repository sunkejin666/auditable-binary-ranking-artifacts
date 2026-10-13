"""Failure-preserving recovery events for real-binary interval actions.

Version 0.3 keeps the 2026-10-09 v0.2 implementation unchanged for artifact
replay.  It treats an action result as effective only when the proposed
interval is nested, the recovered value is covered, and no timeout or exception
occurred.  Otherwise the effective interval remains the pre-action interval.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import time
from dataclasses import asdict, dataclass
from fractions import Fraction
from pathlib import Path
from typing import Any, Iterable


UNKNOWN = "unknown"


def _fraction(value: Any) -> Fraction:
    if isinstance(value, Fraction):
        return value
    if isinstance(value, bool):
        return Fraction(int(value), 1)
    if isinstance(value, int):
        return Fraction(value, 1)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"non-finite numeric value: {value!r}")
        return Fraction(str(value))
    return Fraction(str(value))


def _interval(value: Iterable[Any]) -> tuple[Any, Any]:
    result = tuple(value)
    if len(result) != 2:
        raise ValueError(f"interval must have two endpoints: {result!r}")
    if _fraction(result[0]) > _fraction(result[1]):
        raise ValueError(f"interval lower endpoint exceeds upper: {result!r}")
    return result[0], result[1]


def interval_contains(outer: Iterable[Any], inner: Iterable[Any]) -> bool:
    lo, hi = (_fraction(v) for v in _interval(outer))
    ilo, ihi = (_fraction(v) for v in _interval(inner))
    return lo <= ilo <= ihi <= hi


def value_in_interval(value: Any, interval: Iterable[Any]) -> bool:
    if value in (None, UNKNOWN, ""):
        return True
    lo, hi = (_fraction(v) for v in _interval(interval))
    return lo <= _fraction(value) <= hi


@dataclass(frozen=True)
class RecoveryEvent:
    binary_sha256: str
    project_cve_cluster: str
    variant: str
    candidate_id: str
    component: str
    interval_before: tuple[Any, Any]
    proposed_interval_after: tuple[Any, Any]
    interval_after: tuple[Any, Any]
    recovered_value: Any
    nested_interval: bool
    contract_valid: bool
    action_id: str
    declared_cost: int
    measured_wall_seconds: float
    tool_hash: str
    container_hash: str
    timeout: bool
    exception: str
    extraction_status: str
    candidate_pool_sha256: str
    protocol_sha256: str
    shared_cost_group: str = ""


def _event_digest(payload: dict[str, Any]) -> str:
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class AppendOnlyEventLog:
    """Append canonical JSON events after verifying the existing hash chain."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.previous_hash = "0" * 64
        if not path.exists() or not path.stat().st_size:
            return
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            item = json.loads(line)
            recorded = item.pop("event_sha256", "")
            if item.get("prev_event_sha256") != self.previous_hash:
                raise ValueError(f"hash-chain predecessor mismatch at line {line_no}")
            computed = _event_digest(item)
            if recorded != computed:
                raise ValueError(f"event digest mismatch at line {line_no}")
            self.previous_hash = recorded

    def append(self, event: RecoveryEvent) -> dict[str, Any]:
        payload = asdict(event)
        for key in ("interval_before", "proposed_interval_after", "interval_after"):
            payload[key] = list(payload[key])
        payload["prev_event_sha256"] = self.previous_hash
        payload["event_sha256"] = _event_digest(payload)
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(payload, sort_keys=True, ensure_ascii=False) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        self.previous_hash = payload["event_sha256"]
        return payload


def make_event(
    *,
    binary_sha256: str,
    project_cve_cluster: str,
    variant: str,
    candidate_id: str,
    component: str,
    interval_before: tuple[Any, Any],
    recovered_value: Any,
    interval_after: tuple[Any, Any],
    action_id: str,
    declared_cost: int,
    measured_wall_seconds: float,
    tool_hash: str,
    container_hash: str,
    timeout: bool,
    exception: str,
    extraction_status: str,
    candidate_pool_sha256: str,
    protocol_sha256: str,
    shared_cost_group: str = "",
) -> RecoveryEvent:
    if declared_cost < 0:
        raise ValueError("declared action cost must be non-negative")
    before = _interval(interval_before)
    proposed = _interval(interval_after)
    nested = interval_contains(before, proposed)
    value_covered = value_in_interval(recovered_value, proposed)
    contract_valid = nested and value_covered and not timeout and not exception
    status = extraction_status
    if timeout:
        status = "timeout"
    elif exception:
        status = "error"
    elif not nested:
        status = "unknown_non_nested"
    elif not value_covered:
        status = "unknown_value_outside_interval"
    effective = proposed if contract_valid else before
    effective_value = recovered_value if contract_valid else UNKNOWN
    return RecoveryEvent(
        binary_sha256=binary_sha256,
        project_cve_cluster=project_cve_cluster,
        variant=variant,
        candidate_id=candidate_id,
        component=component,
        interval_before=before,
        proposed_interval_after=proposed,
        interval_after=effective,
        recovered_value=effective_value,
        nested_interval=nested,
        contract_valid=contract_valid,
        action_id=action_id,
        declared_cost=int(declared_cost),
        measured_wall_seconds=float(measured_wall_seconds),
        tool_hash=tool_hash,
        container_hash=container_hash,
        timeout=bool(timeout),
        exception=exception,
        extraction_status=status,
        candidate_pool_sha256=candidate_pool_sha256,
        protocol_sha256=protocol_sha256,
        shared_cost_group=shared_cost_group,
    )


def timed_call(fn):
    start = time.perf_counter()
    try:
        result = fn()
        return result, time.perf_counter() - start, "", False
    except TimeoutError as exc:
        return None, time.perf_counter() - start, repr(exc), True
    except Exception as exc:
        return None, time.perf_counter() - start, repr(exc), False
