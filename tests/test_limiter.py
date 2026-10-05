"""Tests de core/limiter.py : RateLimiter (seau de jetons).

Les tests utilisent une fausse horloge et de faux « sleep » : ils n'attendent
pas pour de vrai et leurs résultats sont exacts. Les débits choisis (2, 4, 8)
donnent des durées représentables exactement en binaire (0,5 ; 0,25 ; 0,125).
Seuls quelques tests, à la fin, utilisent le vrai temps.
"""

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from netscan.core.limiter import RateLimiter

NAN = float("nan")
INF = float("inf")
START = 1000.0


# --- Outils de test -------------------------------------------------------


class FakeClock:
    """Horloge contrôlée à la main."""

    def __init__(self, start=START):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class Sleeper:
    """Faux time.sleep : enregistre les durées et fait avancer l'horloge."""

    def __init__(self, clock=None):
        self.calls = []
        self.clock = clock

    def __call__(self, seconds):
        self.calls.append(seconds)
        if self.clock is not None:
            self.clock.advance(seconds)


class AsyncSleeper:
    """Faux asyncio.sleep : enregistre les durées et fait avancer l'horloge."""

    def __init__(self, clock=None):
        self.calls = []
        self.clock = clock

    async def __call__(self, seconds):
        self.calls.append(seconds)
        if self.clock is not None:
            self.clock.advance(seconds)


def make(rate=4, burst=1, advance_on_sleep=True):
    """Crée un limiteur branché sur une fausse horloge et de faux sleep."""
    clock = FakeClock()
    sleeper = Sleeper(clock if advance_on_sleep else None)
    async_sleeper = AsyncSleeper(clock if advance_on_sleep else None)
    limiter = RateLimiter(
        rate, burst, clock=clock, sleep=sleeper, async_sleep=async_sleeper
    )
    return SimpleNamespace(
        limiter=limiter, clock=clock, sleeper=sleeper, async_sleeper=async_sleeper
    )


def expected_delays(rate, burst, count):
    """Délais attendus pour `count` réservations faites au même instant."""
    return [max(0.0, (i + 1 - burst) / rate) for i in range(count)]


# --- Construction ---------------------------------------------------------


def test_default_limiter_is_unlimited():
    limiter = RateLimiter()
    assert limiter.rate is None
    assert limiter.burst == 1
    assert limiter.unlimited is True


@pytest.mark.parametrize("rate", [1, 2, 4, 10, 100, 0.5, 0.001, 1e6, 100.5])
def test_accepts_valid_rates(rate):
    limiter = RateLimiter(rate)
    assert limiter.rate == rate
    assert limiter.unlimited is False


def test_rate_is_stored_as_float():
    assert isinstance(RateLimiter(10).rate, float)


@pytest.mark.parametrize(
    "rate",
    [0, 0.0, -1, -0.5, -1000, NAN, INF, -INF, "10", "", "fast", True, False, [10], (10,), {"rate": 10}, b"10"],
)
def test_rejects_invalid_rates(rate):
    with pytest.raises(ValueError):
        RateLimiter(rate)


@pytest.mark.parametrize("burst", [1, 2, 3, 10, 1000])
def test_accepts_valid_bursts(burst):
    assert RateLimiter(10, burst).burst == burst


@pytest.mark.parametrize(
    "burst", [0, -1, -10, 1.0, 1.5, 2.0, "1", "", None, True, False, [1], (1,), NAN]
)
def test_rejects_invalid_bursts(burst):
    with pytest.raises(ValueError):
        RateLimiter(10, burst)


def test_burst_is_validated_even_when_unlimited():
    with pytest.raises(ValueError):
        RateLimiter(None, 0)


def test_error_messages_mention_the_parameter():
    with pytest.raises(ValueError, match="(?i)rate"):
        RateLimiter(-1)
    with pytest.raises(ValueError, match="(?i)burst"):
        RateLimiter(10, 0)


def test_burst_can_be_given_by_keyword():
    assert RateLimiter(rate=10, burst=3).burst == 3


def test_clock_and_sleep_are_keyword_only():
    with pytest.raises(TypeError):
        RateLimiter(10, 1, time.monotonic)


def test_properties_are_read_only():
    limiter = RateLimiter(10, 2)
    with pytest.raises(AttributeError):
        limiter.rate = 5
    with pytest.raises(AttributeError):
        limiter.burst = 5
    with pytest.raises(AttributeError):
        limiter.unlimited = True


def test_a_limiter_can_be_created_with_the_default_clock_and_sleeps():
    limiter = RateLimiter(10)
    assert limiter.reserve() == 0.0


def test_two_limiters_are_independent():
    a = make(rate=4, burst=1)
    b = make(rate=4, burst=1)
    assert a.limiter.reserve() == 0.0
    assert a.limiter.reserve() == pytest.approx(0.25)
    assert b.limiter.reserve() == 0.0


# --- repr -----------------------------------------------------------------


def test_repr_of_a_limited_limiter():
    assert repr(RateLimiter(10, 2)) == "RateLimiter(rate=10.0, burst=2)"


def test_repr_of_an_unlimited_limiter():
    assert repr(RateLimiter()) == "RateLimiter(rate=None, burst=1)"


# --- Illimité -------------------------------------------------------------


def test_unlimited_reserve_is_always_zero():
    env = make(rate=None)
    assert [env.limiter.reserve() for _ in range(1000)] == [0.0] * 1000


def test_unlimited_with_a_burst_is_still_unlimited():
    env = make(rate=None, burst=5)
    assert [env.limiter.reserve() for _ in range(50)] == [0.0] * 50


def test_unlimited_acquire_never_sleeps():
    env = make(rate=None)
    assert [env.limiter.acquire() for _ in range(100)] == [0.0] * 100
    assert env.sleeper.calls == []


def test_unlimited_acquire_async_never_sleeps():
    env = make(rate=None)

    async def main():
        return [await env.limiter.acquire_async() for _ in range(100)]

    assert asyncio.run(main()) == [0.0] * 100
    assert env.async_sleeper.calls == []


def test_unlimited_reset_is_harmless():
    limiter = RateLimiter()
    limiter.reset()
    assert limiter.reserve() == 0.0


# --- reserve : formule du seau de jetons ----------------------------------


def test_first_reserve_is_immediate():
    assert make(rate=4, burst=1).limiter.reserve() == 0.0


def test_reserve_returns_a_float():
    env = make(rate=4, burst=1)
    assert isinstance(env.limiter.reserve(), float)
    assert isinstance(env.limiter.reserve(), float)


def test_reserve_spaces_simultaneous_calls_by_one_interval():
    env = make(rate=4, burst=1)
    delays = [env.limiter.reserve() for _ in range(5)]
    assert delays == pytest.approx([0.0, 0.25, 0.5, 0.75, 1.0])


def test_reserve_with_a_slow_rate():
    env = make(rate=0.5, burst=1)
    delays = [env.limiter.reserve() for _ in range(4)]
    assert delays == pytest.approx([0.0, 2.0, 4.0, 6.0])


def test_reserve_with_a_burst_lets_the_first_calls_through():
    env = make(rate=4, burst=3)
    delays = [env.limiter.reserve() for _ in range(6)]
    assert delays == pytest.approx([0.0, 0.0, 0.0, 0.25, 0.5, 0.75])


@pytest.mark.parametrize(
    "rate, burst",
    [(1, 1), (2, 1), (4, 1), (10, 1), (10, 5), (100, 10), (0.5, 2), (1000, 1), (3, 3), (8, 4), (50, 50)],
)
def test_reserve_matches_the_token_bucket_formula(rate, burst):
    env = make(rate=rate, burst=burst)
    delays = [env.limiter.reserve() for _ in range(20)]
    assert delays == pytest.approx(expected_delays(rate, burst, 20))


@pytest.mark.parametrize("rate, burst", [(1, 1), (4, 3), (10, 5), (0.5, 2), (100, 10)])
def test_reserve_never_returns_a_negative_delay(rate, burst):
    env = make(rate=rate, burst=burst)
    assert all(env.limiter.reserve() >= 0.0 for _ in range(50))


@pytest.mark.parametrize("rate, burst", [(1, 1), (4, 3), (10, 5), (0.5, 2), (100, 10)])
def test_simultaneous_delays_never_decrease(rate, burst):
    env = make(rate=rate, burst=burst)
    delays = [env.limiter.reserve() for _ in range(50)]
    assert delays == sorted(delays)


@pytest.mark.parametrize("burst", [1, 2, 5, 10])
def test_exactly_burst_calls_are_immediate(burst):
    env = make(rate=4, burst=burst)
    delays = [env.limiter.reserve() for _ in range(burst + 1)]
    assert delays[:burst] == [0.0] * burst
    assert delays[burst] == pytest.approx(0.25)


def test_reserve_with_a_very_high_rate_gives_tiny_delays():
    env = make(rate=1e6, burst=1)
    delays = [env.limiter.reserve() for _ in range(4)]
    assert delays == pytest.approx([0.0, 1e-6, 2e-6, 3e-6])


def test_reserve_with_a_very_low_rate_gives_huge_delays():
    env = make(rate=0.001, burst=1)
    assert env.limiter.reserve() == 0.0
    assert env.limiter.reserve() == pytest.approx(1000.0)


def test_reserve_never_sleeps():
    env = make(rate=4, burst=1)
    for _ in range(20):
        env.limiter.reserve()
    assert env.sleeper.calls == []
    assert env.async_sleeper.calls == []


def test_reserve_does_not_move_the_clock():
    env = make(rate=4, burst=1)
    for _ in range(20):
        env.limiter.reserve()
    assert env.clock.now == START


# --- reserve : effet du temps ---------------------------------------------


def test_waiting_exactly_one_interval_makes_the_next_call_immediate():
    env = make(rate=4, burst=1)
    assert env.limiter.reserve() == 0.0
    env.clock.advance(0.25)
    assert env.limiter.reserve() == 0.0


def test_waiting_half_an_interval_leaves_half_to_wait():
    env = make(rate=4, burst=1)
    assert env.limiter.reserve() == 0.0
    env.clock.advance(0.125)
    assert env.limiter.reserve() == pytest.approx(0.125)


def test_waiting_more_than_an_interval_does_not_bank_extra_credit():
    env = make(rate=4, burst=1)
    assert env.limiter.reserve() == 0.0
    env.clock.advance(5.0)
    assert env.limiter.reserve() == 0.0
    # Le seau ne contient qu'un jeton : l'appel suivant doit attendre.
    assert env.limiter.reserve() == pytest.approx(0.25)


def test_idle_time_refills_the_bucket_up_to_burst_only():
    env = make(rate=4, burst=3)
    assert [env.limiter.reserve() for _ in range(3)] == [0.0, 0.0, 0.0]
    env.clock.advance(100.0)
    assert [env.limiter.reserve() for _ in range(3)] == [0.0, 0.0, 0.0]
    assert env.limiter.reserve() == pytest.approx(0.25)


def test_partial_refill_with_a_burst():
    env = make(rate=4, burst=3)
    for _ in range(3):
        env.limiter.reserve()
    env.clock.advance(0.5)  # 2 jetons regagnés
    assert [env.limiter.reserve() for _ in range(2)] == [0.0, 0.0]
    assert env.limiter.reserve() == pytest.approx(0.25)


def test_bucket_starts_full_even_if_time_passes_before_the_first_call():
    env = make(rate=4, burst=1)
    env.clock.advance(100.0)
    assert env.limiter.reserve() == 0.0
    assert env.limiter.reserve() == pytest.approx(0.25)


def test_a_clock_going_backwards_counts_as_no_time_elapsed():
    env = make(rate=4, burst=1)
    assert env.limiter.reserve() == 0.0
    env.clock.now -= 50.0
    assert env.limiter.reserve() == pytest.approx(0.25)


def test_after_a_clock_jump_back_the_limiter_keeps_working():
    env = make(rate=4, burst=1)
    env.limiter.reserve()
    env.clock.now -= 50.0
    env.limiter.reserve()
    env.clock.advance(0.5)  # depuis le nouvel instant de référence : 2 jetons
    assert env.limiter.reserve() == 0.0
    assert env.limiter.reserve() == pytest.approx(0.25)


def test_debt_is_repaid_over_time():
    env = make(rate=4, burst=1)
    for _ in range(100):
        env.limiter.reserve()
    # 100 créneaux ont été réservés : le 101e est à 25 s (100 / 4).
    env.clock.advance(5.0)
    assert env.limiter.reserve() == pytest.approx(20.0)


def test_a_long_pause_repays_all_the_debt_but_does_not_exceed_burst():
    env = make(rate=4, burst=1)
    for _ in range(100):
        env.limiter.reserve()
    env.clock.advance(1000.0)
    assert env.limiter.reserve() == 0.0
    assert env.limiter.reserve() == pytest.approx(0.25)


def test_a_consumer_slower_than_the_rate_never_waits():
    env = make(rate=4, burst=1)
    delays = []
    for _ in range(10):
        delays.append(env.limiter.reserve())
        env.clock.advance(0.25)
    assert delays == [0.0] * 10


def test_a_consumer_faster_than_the_rate_waits_for_the_difference():
    env = make(rate=4, burst=1)
    delays = []
    for _ in range(5):
        delays.append(env.limiter.reserve())
        env.clock.advance(0.125)
    # Le consommateur revient deux fois trop vite : la dette grandit.
    assert delays == pytest.approx([0.0, 0.125, 0.25, 0.375, 0.5])


# --- acquire (synchrone) --------------------------------------------------


def test_acquire_does_not_sleep_when_a_token_is_available():
    env = make(rate=4, burst=1)
    assert env.limiter.acquire() == 0.0
    assert env.sleeper.calls == []


def test_acquire_sleeps_for_the_missing_time():
    env = make(rate=4, burst=1)
    env.limiter.acquire()
    delay = env.limiter.acquire()
    assert delay == pytest.approx(0.25)
    assert env.sleeper.calls == pytest.approx([0.25])


def test_acquire_returns_the_delay_it_waited():
    env = make(rate=4, burst=1)
    env.limiter.acquire()
    assert env.limiter.acquire() == pytest.approx(env.sleeper.calls[0])


def test_acquire_spaces_calls_evenly():
    env = make(rate=4, burst=1)
    for _ in range(5):
        env.limiter.acquire()
    assert env.sleeper.calls == pytest.approx([0.25] * 4)
    assert env.clock.now - START == pytest.approx(1.0)


@pytest.mark.parametrize("rate, burst", [(4, 1), (4, 3), (2, 2), (10, 1), (10, 5), (8, 4)])
def test_total_time_of_n_acquires(rate, burst):
    env = make(rate=rate, burst=burst)
    count = 30
    for _ in range(count):
        env.limiter.acquire()
    assert env.clock.now - START == pytest.approx((count - burst) / rate)


@pytest.mark.parametrize("burst", [5, 10, 30])
def test_fewer_acquires_than_burst_never_wait(burst):
    env = make(rate=4, burst=burst)
    for _ in range(5):
        env.limiter.acquire()
    assert env.sleeper.calls == []
    assert env.clock.now == START


def test_acquire_uses_the_injected_sleep_and_not_the_real_one(monkeypatch):
    def forbidden(_seconds):
        raise AssertionError("time.sleep ne doit pas être appelé")

    monkeypatch.setattr(time, "sleep", forbidden)
    env = make(rate=4, burst=1)
    for _ in range(3):
        env.limiter.acquire()
    assert len(env.sleeper.calls) == 2


def test_acquire_and_reserve_share_the_same_bucket():
    env = make(rate=4, burst=1)
    assert env.limiter.reserve() == 0.0
    assert env.limiter.acquire() == pytest.approx(0.25)


# --- acquire_async --------------------------------------------------------


def test_acquire_async_does_not_sleep_when_a_token_is_available():
    env = make(rate=4, burst=1)
    assert asyncio.run(env.limiter.acquire_async()) == 0.0
    assert env.async_sleeper.calls == []


def test_acquire_async_sleeps_for_the_missing_time():
    env = make(rate=4, burst=1)

    async def main():
        await env.limiter.acquire_async()
        return await env.limiter.acquire_async()

    assert asyncio.run(main()) == pytest.approx(0.25)
    assert env.async_sleeper.calls == pytest.approx([0.25])


def test_acquire_async_does_not_use_the_synchronous_sleep():
    env = make(rate=4, burst=1)

    async def main():
        for _ in range(3):
            await env.limiter.acquire_async()

    asyncio.run(main())
    assert env.sleeper.calls == []
    assert len(env.async_sleeper.calls) == 2


def test_acquire_async_spaces_sequential_calls_evenly():
    env = make(rate=4, burst=1)

    async def main():
        return [await env.limiter.acquire_async() for _ in range(5)]

    assert asyncio.run(main()) == pytest.approx([0.0, 0.25, 0.25, 0.25, 0.25])
    assert env.clock.now - START == pytest.approx(1.0)


def test_concurrent_tasks_each_get_a_different_slot():
    # L'horloge n'avance pas : c'est la réservation immédiate qui répartit
    # les créneaux entre les tâches lancées en même temps.
    env = make(rate=4, burst=1, advance_on_sleep=False)

    async def main():
        return await asyncio.gather(*(env.limiter.acquire_async() for _ in range(5)))

    assert asyncio.run(main()) == pytest.approx([0.0, 0.25, 0.5, 0.75, 1.0])
    assert env.async_sleeper.calls == pytest.approx([0.25, 0.5, 0.75, 1.0])


def test_concurrent_tasks_with_a_burst():
    env = make(rate=4, burst=3, advance_on_sleep=False)

    async def main():
        return await asyncio.gather(*(env.limiter.acquire_async() for _ in range(6)))

    assert asyncio.run(main()) == pytest.approx([0.0, 0.0, 0.0, 0.25, 0.5, 0.75])


def test_many_concurrent_tasks_get_distinct_increasing_slots():
    env = make(rate=4, burst=1, advance_on_sleep=False)

    async def main():
        return await asyncio.gather(*(env.limiter.acquire_async() for _ in range(100)))

    delays = asyncio.run(main())
    assert delays == pytest.approx([i / 4 for i in range(100)])
    assert len(set(delays)) == 100


def test_async_and_sync_share_the_same_bucket():
    env = make(rate=4, burst=1)
    assert env.limiter.reserve() == 0.0
    assert asyncio.run(env.limiter.acquire_async()) == pytest.approx(0.25)


# --- Threads --------------------------------------------------------------


def test_reserve_is_thread_safe():
    env = make(rate=10, burst=1)
    with ThreadPoolExecutor(max_workers=16) as pool:
        delays = list(pool.map(lambda _: env.limiter.reserve(), range(200)))
    assert sorted(delays) == pytest.approx([i / 10 for i in range(200)])


def test_reserve_is_thread_safe_with_a_burst():
    env = make(rate=10, burst=5)
    with ThreadPoolExecutor(max_workers=16) as pool:
        delays = list(pool.map(lambda _: env.limiter.reserve(), range(100)))
    assert sorted(delays) == pytest.approx(expected_delays(10, 5, 100))


def test_acquire_from_several_threads_never_loses_a_call():
    env = make(rate=10, burst=1, advance_on_sleep=False)
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda _: env.limiter.acquire(), range(50)))
    assert len(env.sleeper.calls) == 49  # le premier appel est immédiat


# --- reset ----------------------------------------------------------------


def test_reset_refills_the_bucket():
    env = make(rate=4, burst=3)
    for _ in range(10):
        env.limiter.reserve()
    env.limiter.reset()
    assert [env.limiter.reserve() for _ in range(3)] == [0.0, 0.0, 0.0]
    assert env.limiter.reserve() == pytest.approx(0.25)


def test_reset_forgets_the_debt():
    env = make(rate=4, burst=1)
    for _ in range(100):
        env.limiter.reserve()
    env.limiter.reset()
    assert env.limiter.reserve() == 0.0


def test_reset_reads_the_clock_again():
    env = make(rate=4, burst=1)
    env.limiter.reserve()
    env.clock.advance(1000.0)
    env.limiter.reset()
    assert env.limiter.reserve() == 0.0
    assert env.limiter.reserve() == pytest.approx(0.25)


def test_reset_on_a_fresh_limiter_changes_nothing():
    env = make(rate=4, burst=2)
    env.limiter.reset()
    assert [env.limiter.reserve() for _ in range(3)] == pytest.approx([0.0, 0.0, 0.25])


def test_reset_keeps_rate_and_burst():
    limiter = RateLimiter(10, 3)
    limiter.reset()
    assert limiter.rate == 10
    assert limiter.burst == 3


def test_reset_returns_none():
    assert RateLimiter(10).reset() is None


# --- Avec le vrai temps (bornes larges pour éviter les faux échecs) -------


def test_acquire_really_waits_with_the_default_sleep():
    limiter = RateLimiter(rate=200, burst=1)  # 5 ms entre deux appels
    start = time.monotonic()
    for _ in range(5):
        limiter.acquire()
    elapsed = time.monotonic() - start
    assert 0.015 <= elapsed < 2.0


def test_acquire_async_really_waits_with_the_default_sleep():
    limiter = RateLimiter(rate=200, burst=1)

    async def main():
        await asyncio.gather(*(limiter.acquire_async() for _ in range(5)))

    start = time.monotonic()
    asyncio.run(main())
    elapsed = time.monotonic() - start
    assert 0.015 <= elapsed < 2.0


def test_unlimited_is_really_fast():
    limiter = RateLimiter()
    start = time.monotonic()
    for _ in range(10_000):
        limiter.acquire()
    assert time.monotonic() - start < 1.0