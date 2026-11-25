def part_count(size_bytes: int, part_size: int) -> int:
    if size_bytes <= 0:
        raise ValueError("size_bytes must be positive")
    if part_size <= 0:
        raise ValueError("part_size must be positive")
    return (size_bytes + part_size - 1) // part_size


def part_ranges(size_bytes: int, part_size: int) -> list[tuple[int, int]]:
    return [
        (start, min(start + part_size, size_bytes) - 1) for start in range(0, size_bytes, part_size)
    ]
