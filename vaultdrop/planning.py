MIN_PART_SIZE = 5 * 1024 * 1024
MAX_PARTS = 10_000
MAX_OBJECT_SIZE = 5 * 1024**4


def part_count(size_bytes: int, part_size: int) -> int:
    if size_bytes <= 0:
        raise ValueError("size_bytes must be positive")
    if part_size < MIN_PART_SIZE:
        raise ValueError("part_size must be at least 5 MiB")
    if size_bytes > MAX_OBJECT_SIZE:
        raise ValueError("object exceeds 5 TiB")
    count = (size_bytes + part_size - 1) // part_size
    if count > MAX_PARTS:
        raise ValueError("part count exceeds 10000")
    return count


def part_length(size_bytes: int, part_size: int, part_number: int) -> int:
    """Exact byte length S3 must hold for 1-based `part_number`."""
    count = part_count(size_bytes, part_size)
    if not 1 <= part_number <= count:
        raise ValueError("part_number out of range")
    if part_number < count:
        return part_size
    return size_bytes - (count - 1) * part_size


def part_ranges(size_bytes: int, part_size: int) -> list[tuple[int, int]]:
    """Inclusive (start, end) byte offsets of every part."""
    return [
        (start, min(start + part_size, size_bytes) - 1) for start in range(0, size_bytes, part_size)
    ]
