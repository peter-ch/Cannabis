"""One retained service deadline, shared by all stages inside one guest.

The caller must authenticate the service interval and provide trustworthy guest
time. This does not solve host-controlled clock, VM pause or snapshot rollback.
"""
from dataclasses import dataclass
import math
import time


@dataclass(frozen=True)
class ExecutionDeadline:
    monotonic_end: float

    def __post_init__(self):
        if (type(self.monotonic_end) not in (int, float) or not math.isfinite(self.monotonic_end)
                or not 0 <= self.monotonic_end <= time.monotonic() + 90 * 86400):
            raise ValueError('Require a finite absolute monotonic service deadline')

    @classmethod
    def from_service_interval(cls, start, end):
        """Convert an independently verified UTC interval exactly once.

        Later helpers receive this object, never another conversion of the
        original duration. Sampling the monotonic clock first is conservative.
        """
        if any(type(value) is not int or not 0 < value < 2**53 for value in (start, end)) or not 0 < end - start <= 90 * 86400:
            raise ValueError('Require a bounded signed service interval')
        monotonic, wall = time.monotonic(), time.time()
        if not start <= wall < end:
            raise RuntimeError('Signed service interval is not active')
        return cls(monotonic + end - wall)

    def check(self, cancelled=None):
        if cancelled is not None and cancelled.is_set():
            raise RuntimeError('Guest service cancelled')
        if time.monotonic() >= self.monotonic_end:
            raise RuntimeError('Guest service deadline expired')


def bounded_stage_deadline(wall_seconds, deadline=None):
    """An individual stage can shorten a reservation, never extend it."""
    if deadline is not None:
        if not isinstance(deadline, ExecutionDeadline):
            raise ValueError('Require a retained ExecutionDeadline')
        deadline.check()
    own_end = time.monotonic() + wall_seconds
    return min(own_end, deadline.monotonic_end) if deadline is not None else own_end
