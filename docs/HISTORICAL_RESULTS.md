# Historical results from the original presentation

This file records measurements stated in the original
`HPC_Presentation.pdf`. They are preserved as **historical claims**, not as
results reproduced by the modern implementation.

The original presentation does not provide enough information to reconstruct
all benchmark conditions: machine model, JVM/JCE version, exact code revision,
warm-up policy, number of repetitions, and precise effective DES key-space
definition are not fully specified.

## Exhaustive search

The presentation states that exhaustive search encrypts a known plaintext with
candidate keys and compares against the target ciphertext.

It reports:

| Historical key-space label | Historical result |
| --- | ---: |
| 24 bits of entropy | 78 seconds on average |
| 32 bits of entropy | `5,525` (historical slide notation) |

The extracted slide text does not make the unit following `5,525` fully
unambiguous. The value is therefore preserved rather than silently
reinterpreted.

## Hellman TMTO — historical 16-bit label

The presentation gives `m = 10,000`, `t = 10`:

| Run | Offline | Online | Result | False alarms |
| ---: | ---: | ---: | --- | ---: |
| 1 | 1.929 s | 0.050 s | key found | 0 |
| 2 | 1.896 s | 0.092 s | key found | 3 |
| 3 | 1.900 s | 0.004 s | key found | 0 |

## Hellman TMTO — historical 32-bit label

For `m = 10`, `t = 100,000`:

| Run | Offline | Online | Result | False alarms |
| ---: | ---: | ---: | --- | ---: |
| 1 | 14.956 s | 122.934 s | not found | 220 |
| 2 | 22.652 s | 247.143 s | not found | 90 |

For `m = 100,000`, `t = 10`:

| Run | Offline | Online | Result | False alarms |
| ---: | ---: | ---: | --- | ---: |
| 1 | 5.364 s | 34.917 s | not found | 0 |
| 2 | 3.656 s | 12.110 s | not found | 0 |

## Distinguished-points TMTO — historical 32-bit label

For `m = 10`, `t = 100,000`:

| Run | Offline | Online | Result | False alarms |
| ---: | ---: | ---: | --- | ---: |
| 1 | 11.234 s | 2.035 s | not found | 5 |
| 2 | 8.078 s | 1.960 s | not found | 3 |

For `m = 100,000`, `t = 100`:

| Run | Offline | Online | Result | False alarms |
| ---: | ---: | ---: | --- | ---: |
| 1 | 103.662 s | 0.002 s | not found | 0 |
| 2 | 112.268 s | 0.001 s | not found | 0 |

## Why these results are separated from the modern benchmark

The checked-in historical Java prototype varies four raw DES bytes while DES
ignores one parity bit per byte. Consequently, a four-byte raw representation
does not automatically constitute 32 independent effective DES key bits.

The historical online Hellman implementation also performs repeated linear
endpoint scans, whereas the modern implementation indexes endpoints.

For those reasons, the values above are useful provenance but should not be
presented as measurements of the modern code.
