from typing import Union

from jwt.utils import bytes_from_int, base64url_encode, base64url_decode


def to_base64url_uint(val: int) -> bytes:
    if val < 0:
        raise ValueError("Must be a positive integer")

    int_bytes = bytes_from_int(val)

    if len(int_bytes) == 0:
        int_bytes = b"\x00"

    return base64url_encode(int_bytes)


def from_base64url_uint(val: Union[str, bytes]) -> int:
    if isinstance(val, str):
        val = val.encode("ascii")

    data = base64url_decode(val)
    return int.from_bytes(data, byteorder="big")
