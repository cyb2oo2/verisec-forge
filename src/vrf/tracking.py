from __future__ import annotations

from vrf.io_utils import append_jsonl
from vrf.schemas import ExperimentRecord


def log_experiment(record: ExperimentRecord, tracker_path: str) -> None:
    append_jsonl(tracker_path, record.to_dict())
