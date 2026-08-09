"""Keep GPU work inside a budget so a run does not monopolise the card.

A single consumer GPU is also the machine's display adapter. A job that takes
every byte of VRAM and every SM makes the desktop unusable and, worse, competes
with itself against the compositor. These helpers let a run reserve only part of
the card.

Both knobs are read from the environment so that **defaults are unchanged**:
with neither set, every script behaves exactly as it did before, and every
result already published remains reproducible.

``VRF_GPU_MEMORY_FRACTION``
    Float in ``(0, 1]``. Caps this process at that fraction of total VRAM via
    ``torch.cuda.set_per_process_memory_fraction``. Allocations past the cap
    raise ``torch.OutOfMemoryError`` inside this process instead of starving
    everything else on the card. Prefer a cap plus a smaller batch size over
    letting the allocator expand to fill the device.

``VRF_GPU_THROTTLE_MS``
    Integer milliseconds to sleep between batches/steps. Yields the SMs
    periodically so the display stays responsive. Costs wall-clock roughly in
    proportion to (throttle / batch time), so keep it small: 10-50 ms is
    usually enough to keep a desktop smooth.
"""

from __future__ import annotations

import os
import time
from typing import Any, Callable


def _read_fraction() -> float | None:
    raw = os.environ.get("VRF_GPU_MEMORY_FRACTION", "").strip()
    if not raw:
        return None
    value = float(raw)
    if not 0.0 < value <= 1.0:
        raise ValueError(
            f"VRF_GPU_MEMORY_FRACTION must be in (0, 1], got {value!r}"
        )
    return value


def _read_throttle_seconds() -> float:
    raw = os.environ.get("VRF_GPU_THROTTLE_MS", "").strip()
    if not raw:
        return 0.0
    value = int(raw)
    if value < 0:
        raise ValueError(f"VRF_GPU_THROTTLE_MS must be >= 0, got {value!r}")
    return value / 1000.0


def apply_gpu_budget(torch_module: Any, *, device: int = 0) -> dict[str, Any]:
    """Apply the configured VRAM cap. Returns what was applied, for logging."""
    fraction = _read_fraction()
    throttle = _read_throttle_seconds()
    applied: dict[str, Any] = {
        "memory_fraction": fraction,
        "throttle_ms": int(throttle * 1000),
        "capped": False,
    }
    cuda = getattr(torch_module, "cuda", None)
    if fraction is not None and cuda is not None and cuda.is_available():
        cuda.set_per_process_memory_fraction(fraction, device)
        total = cuda.get_device_properties(device).total_memory
        applied["capped"] = True
        applied["budget_gib"] = round(fraction * total / 1024**3, 2)
        applied["device_total_gib"] = round(total / 1024**3, 2)
    return applied


def make_throttle() -> Callable[[], None]:
    """Return a no-arg callable that sleeps the configured throttle interval.

    Returns a no-op when unset, so callers can invoke it unconditionally in a
    hot loop without branching.
    """
    seconds = _read_throttle_seconds()
    if seconds <= 0:
        return lambda: None
    return lambda: time.sleep(seconds)


def describe(applied: dict[str, Any]) -> str:
    if not applied.get("capped"):
        base = "gpu budget: uncapped"
    else:
        base = (
            f"gpu budget: {applied['budget_gib']} GiB of "
            f"{applied['device_total_gib']} GiB "
            f"({applied['memory_fraction']:.0%})"
        )
    if applied.get("throttle_ms"):
        base += f", throttle {applied['throttle_ms']} ms/batch"
    return base


def throttle_callback(transformers_module: Any) -> Any | None:
    """A ``TrainerCallback`` that yields the GPU between optimizer steps.

    Returns ``None`` when throttling is unset so callers can skip adding it.
    """
    seconds = _read_throttle_seconds()
    if seconds <= 0:
        return None

    class GpuThrottleCallback(transformers_module.TrainerCallback):
        def on_step_end(self, args, state, control, **kwargs):
            time.sleep(seconds)
            return control

    return GpuThrottleCallback()
