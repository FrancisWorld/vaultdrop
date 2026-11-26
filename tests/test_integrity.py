import hashlib
import tracemalloc
from collections.abc import Iterator

from hypothesis import given
from hypothesis import strategies as st

from vaultdrop.integrity import hash_parts
from vaultdrop.planning import part_length, part_ranges


@given(
    chunks=st.lists(st.binary(max_size=300), max_size=20),
    part_size=st.integers(min_value=1, max_value=250),
)
def test_hash_parts_matches_naive_hashing(chunks: list[bytes], part_size: int) -> None:
    data = b"".join(chunks)
    whole, parts, total = hash_parts(iter(chunks), part_size)
    assert total == len(data)
    assert whole == hashlib.sha256(data).hexdigest()
    expected = [
        hashlib.sha256(data[i : i + part_size]).hexdigest() for i in range(0, len(data), part_size)
    ]
    assert parts == expected


@given(size=st.integers(1, 10**10), part_size=st.integers(5 * 1024 * 1024, 10**8))
def test_part_lengths_sum_to_object_size(size: int, part_size: int) -> None:
    ranges = part_ranges(size, part_size)
    lengths = [part_length(size, part_size, n) for n in range(1, len(ranges) + 1)]
    assert sum(lengths) == size
    assert lengths == [end - start + 1 for start, end in ranges]


def test_hashing_memory_is_bounded_by_the_chunk_size() -> None:
    chunk = bytes(1024 * 1024)

    def stream() -> Iterator[bytes]:
        for _ in range(96):  # 96 MiB streamed through
            yield chunk

    tracemalloc.start()
    whole, parts, total = hash_parts(stream(), 8 * 1024 * 1024)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert total == 96 * 1024 * 1024
    assert len(parts) == 12
    assert whole == hashlib.sha256(chunk * 96).hexdigest()
    assert peak < 2 * 1024 * 1024
