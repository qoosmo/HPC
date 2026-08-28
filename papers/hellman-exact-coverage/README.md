# Paper 1 — Hellman / DP exact coverage

This directory contains the focused ePrint paper. It is intentionally separate
from `research-note/`, which preserves the earlier combined AES/TMTO
reconstruction.

Build:

```bash
cd papers/hellman-exact-coverage
pdflatex main.tex
bibtex main
pdflatex main.tex
pdflatex main.tex
```

The paper is modular: every scientific section lives in `sections/` and is
reviewed independently before the final assembly.

The abstract is provisional until all experiment sweeps are complete.
