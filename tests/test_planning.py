from hypothesis import given
from hypothesis import strategies as st

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
