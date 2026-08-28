# Research note

This directory contains the updated research note for the project.

The note is intentionally separate from the historical coursework presentation
stored at `../docs/original-presentation.pdf`.

Build with:

```bash
latexmk -pdf -interaction=nonstopmode -halt-on-error main.tex
```

The Java implementation is the current reference implementation. A Rust port is
planned as a later phase, with cross-language equivalence tests before any
performance comparison.
