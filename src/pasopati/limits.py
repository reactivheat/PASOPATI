"""Shared monotonic deadlines, attempt/rate limits and concurrency for real callers."""

import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Protocol

from pasopati.core.errors import PolicyError
from pasopati.profiles import Profile


class Clock(Protocol):
    def monotonic(self) -> float: ...
    def sleep(self, seconds: float) -> None: ...


class SystemClock:
    def monotonic(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


@dataclass(frozen=True)
class Deadline:
    end: float
    clock: Clock

    def remaining(self, limit: float | None = None) -> float:
        remaining = self.end - self.clock.monotonic()
        if remaining <= 0:
            raise PolicyError("timeout")
        return min(remaining, limit) if limit is not None else remaining


class RequestBudget:
    """One limiter shared across provider HTTP attempts and discovery DNS RR lookups."""

    def __init__(self, profile: Profile, clock: Clock | None = None) -> None:
        self.profile = profile
        self.clock = clock or SystemClock()
        self._slots = threading.BoundedSemaphore(profile.concurrency)
        self._lock = threading.Lock()
        self._used = 0
        self._next_request = 0.0

    @property
    def used(self) -> int:
        with self._lock:
            return self._used

    @contextmanager
    def slot(self, deadline: Deadline) -> Iterator[None]:
        if not self._slots.acquire(timeout=deadline.remaining()):
            raise PolicyError("timeout")
        try:
            yield
        finally:
            self._slots.release()

    def reserve(self, deadline: Deadline) -> None:
        if not self.profile.network_enabled:
            raise PolicyError("passive_profile")
        if not self._lock.acquire(timeout=deadline.remaining()):
            raise PolicyError("timeout")
        try:
            if self._used >= self.profile.request_budget:
                raise PolicyError("budget_exhausted")
            delay = max(0.0, self._next_request - self.clock.monotonic())
            if delay >= deadline.remaining():
                raise PolicyError("timeout")
            if delay:
                self.clock.sleep(delay)
            deadline.remaining()
            self._used += 1
            self._next_request = self.clock.monotonic() + 1.0 / self.profile.requests_per_second
        finally:
            self._lock.release()
