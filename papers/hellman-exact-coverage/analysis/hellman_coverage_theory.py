#!/usr/bin/env python3
"""Random-function Hellman coverage baseline following Ma & Hong (2009).

For independently chosen starts:
    s_0 = 0
    s_{k+1} = 1 - exp(-m/N) exp(-s_k)
    ECR(N,m,t) = N/(m*t) * s_t

Here s_t is the expected fraction of the whole state space covered after
t columns under the approximation.
"""
import argparse
import math

def estimate(N: int, m: int, t: int):
    s = 0.0
    for _ in range(t):
        s = 1.0 - math.exp(-m / N) * math.exp(-s)
    ecr = (N / (m * t)) * s
    return s, ecr, s * N

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--N", type=int, default=65536)
    ap.add_argument("--m", type=int, default=1024)
    ap.add_argument("--t", type=int, default=64)
    args = ap.parse_args()

    s, ecr, expected = estimate(args.N, args.m, args.t)
    print(f"N={args.N}")
    print(f"m={args.m}")
    print(f"t={args.t}")
    print(f"mt_over_N={args.m * args.t / args.N:.12f}")
    print(f"mt2_over_N={args.m * args.t * args.t / args.N:.12f}")
    print(f"expected_fraction_of_N={s:.12f}")
    print(f"ECR_fraction_of_mt={ecr:.12f}")
    print(f"expected_distinct_states={expected:.6f}")

if __name__ == "__main__":
    main()
