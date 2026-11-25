from hypothesis import given
from hypothesis import strategies as st

import pytest

from vaultdrop.planning import part_count, part_ranges


@given(
    size=st.integers(min_value=1, max_value=10_000_000_000),
    part=st.integers(min_value=5 * 1024 * 1024, max_value=100 * 1024 * 1024),
)
def test_part_ranges_cover_file(size: int, part: int) -> None:
    ranges = part_ranges(size, part)
    assert ranges[0][0] == 0
    assert ranges[-1][1] == size - 1
    assert part_count(size, part) == len(ranges)
    assert all(end >= start for start, end in ranges)


@given(size=st.integers(min_value=1, max_value=5 * 1024**4))
def test_object_limit_and_part_limit(size: int) -> None:
    part = max(5 * 1024 * 1024, (size + 9999) // 10000)
    count = part_count(size, part)
    assert count <= 10000


def test_part_planning_rejects_invalid_limits() -> None:
    with pytest.raises(ValueError):
        part_count(1, 4 * 1024 * 1024)
    with pytest.raises(ValueError):
        part_count(5 * 1024**4 + 1, 5 * 1024 * 1024)
    with pytest.raises(ValueError):
        part_count(10 * 1024**4, 5 * 1024 * 1024)
