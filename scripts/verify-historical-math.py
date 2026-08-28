#!/usr/bin/env python3
"""Verify historical finite-field formulas transcribed from slides 7, 8, and 12."""

from itertools import product


MODULUS = 0b11111  # x^4 + x^3 + x^2 + x + 1


def gf16_mul(a: int, b: int) -> int:
    prod = 0
    for i in range(4):
        if (b >> i) & 1:
            prod ^= a << i
    for k in range(6, 3, -1):
        if (prod >> k) & 1:
            prod ^= MODULUS << (k - 4)
    return prod & 0xF


def gf16_pow(a: int, e: int) -> int:
    out = 1
    while e:
        if e & 1:
            out = gf16_mul(out, a)
        a = gf16_mul(a, a)
        e >>= 1
    return out


ALPHA = 0b0010
NORMAL_BASIS = (
    gf16_pow(ALPHA, 8),
    gf16_pow(ALPHA, 4),
    gf16_pow(ALPHA, 2),
    gf16_pow(ALPHA, 1),
)


def element(coords):
    value = 0
    for bit, basis_element in zip(coords, NORMAL_BASIS):
        if bit:
            value ^= basis_element
    return value


COORDS = {}
for bits in product((0, 1), repeat=4):
    COORDS[element(bits)] = bits


def slide_product(a, b):
    a3, a2, a1, a0 = a
    b3, b2, b1, b0 = b
    q = (a0 & b2) ^ (a2 & b0) ^ (a1 & b3) ^ (a3 & b1)
    return (
        (a0 & b1) ^ (a1 & b0) ^ (a2 & b2) ^ q,
        (a0 & b3) ^ (a3 & b0) ^ (a1 & b1) ^ q,
        (a2 & b3) ^ (a3 & b2) ^ (a0 & b0) ^ q,
        (a1 & b2) ^ (a2 & b1) ^ (a3 & b3) ^ q,
    )


D = (
    (1, 0, 1, 0, 0, 0, 1, 0),
    (0, 1, 1, 1, 0, 0, 0, 0),
    (1, 1, 0, 1, 1, 1, 0, 0),
    (1, 0, 1, 0, 1, 1, 1, 0),
    (1, 0, 1, 0, 0, 1, 0, 1),
    (1, 0, 1, 0, 0, 0, 0, 1),
    (0, 1, 0, 1, 1, 1, 0, 1),
    (0, 1, 0, 0, 0, 0, 0, 1),
)

D_INV = (
    (1, 1, 0, 1, 0, 1, 1, 0),
    (1, 1, 1, 1, 0, 1, 0, 1),
    (0, 0, 1, 0, 0, 1, 1, 0),
    (1, 0, 0, 1, 0, 0, 1, 1),
    (1, 0, 0, 1, 1, 1, 0, 0),
    (0, 0, 0, 0, 1, 1, 0, 0),
    (0, 1, 1, 1, 0, 0, 0, 0),
    (1, 1, 1, 1, 0, 1, 0, 0),
)


def matmul_gf2(a, b):
    rows = len(a)
    cols = len(b[0])
    inner = len(b)
    return tuple(
        tuple(
            sum(a[i][k] * b[k][j] for k in range(inner)) & 1
            for j in range(cols)
        )
        for i in range(rows)
    )


def identity(n):
    return tuple(tuple(int(i == j) for j in range(n)) for i in range(n))


def main():
    assert len(set(NORMAL_BASIS)) == 4
    assert len(COORDS) == 16

    for a in product((0, 1), repeat=4):
        for b in product((0, 1), repeat=4):
            expected = COORDS[gf16_mul(element(a), element(b))]
            assert slide_product(a, b) == expected

    for a in product((0, 1), repeat=4):
        a3, a2, a1, a0 = a
        expected_square = (a2, a1, a0, a3)
        actual_square = COORDS[gf16_mul(element(a), element(a))]
        assert actual_square == expected_square

    assert matmul_gf2(D, D_INV) == identity(8)
    assert matmul_gf2(D_INV, D) == identity(8)

    print("HISTORICAL_MATH_VERIFICATION=PASS")
    print(f"NORMAL_BASIS={NORMAL_BASIS}")
    print(f"D_HAMMING_WEIGHT={sum(map(sum, D))}")
    print(f"D_INV_HAMMING_WEIGHT={sum(map(sum, D_INV))}")


if __name__ == "__main__":
    main()
