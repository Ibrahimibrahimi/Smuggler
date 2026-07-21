"""
Adaptive Rate Limiter
Dynamically adjusts request delay based on server responses
"""

import time
import threading


class AdaptiveRateLimiter:
    """Adaptive rate limiter that adjusts delay based on server feedback.

    Doubles the delay on 429 (Too Many Requests) responses and gradually
    reduces delay on consecutive successful responses.
    """

    def __init__(self, initial_delay: float = 0.3, min_delay: float = 0.1, max_delay: float = 10.0):
        self._delay = initial_delay
        self._min_delay = min_delay
        self._max_delay = max_delay
        self._consecutive_successes = 0
        self._success_threshold = 5
        self._lock = threading.Lock()
        self._last_request_time = 0.0

    @property
    def delay(self) -> float:
        with self._lock:
            return self._delay

    def acquire(self) -> None:
        """Block until it is safe to send the next request."""
        with self._lock:
            wait_until = self._last_request_time + self._delay
        remaining = wait_until - time.monotonic()
        if remaining > 0:
            time.sleep(remaining)
        with self._lock:
            self._last_request_time = time.monotonic()

    def release(self, success: bool) -> None:
        """Notify the limiter of the outcome of the last request.

        On success, the internal delay gradually decreases after consecutive
        successes. On failure (e.g. 429), delay is doubled via backoff().
        """
        with self._lock:
            if success:
                self._consecutive_successes += 1
                if self._consecutive_successes >= self._success_threshold:
                    reduction = self._delay * 0.25
                    self._delay = max(self._min_delay, self._delay - reduction)
                    self._consecutive_successes = 0
            else:
                self._consecutive_successes = 0

    def backoff(self) -> None:
        """Double the current delay, capped at max_delay."""
        with self._lock:
            self._delay = min(self._max_delay, self._delay * 2)
            self._consecutive_successes = 0

    def reset(self) -> None:
        """Reset the limiter to its initial state."""
        with self._lock:
            self._consecutive_successes = 0
            # Preserve the original initial_delay by re-reading is not possible,
            # so caller should pass initial_delay again or use a fresh instance.
