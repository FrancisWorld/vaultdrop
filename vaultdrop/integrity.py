import hashlib
from collections.abc import Iterable


def hash_parts(chunks: Iterable[bytes], part_size: int) -> tuple[str, list[str], int]:
    """Hash a byte stream once, producing the whole-object and per-part SHA-256 digests.

    Memory use is bounded by the size of one input chunk: nothing is accumulated.
    Returns (whole_hex, [part_hex, ...], total_bytes).
    """
    whole = hashlib.sha256()
    part = hashlib.sha256()
    in_part = 0
    total = 0
    digests: list[str] = []
    for chunk in chunks:
        view = memoryview(chunk)
        while len(view):
            piece = view[: part_size - in_part]
            whole.update(piece)
            part.update(piece)
            in_part += len(piece)
            total += len(piece)
            view = view[len(piece) :]
            if in_part == part_size:
                digests.append(part.hexdigest())
                part = hashlib.sha256()
                in_part = 0
    if in_part:
        digests.append(part.hexdigest())
    return whole.hexdigest(), digests, total
