# ePrint-style research note

This directory contains the evolving paper draft:

```text
cryptanalytic-time-memory-tradeoffs.pdf
main.tex
```

The paper is separate from the original master's research presentation:

```text
../docs/original-presentation.pdf
```

The historical PDF remains unchanged.

`HISTORICAL-MATH-SOURCE.md` maps reconstructed equations to the preserved slides and records what cannot be recovered from the PDF.

The current paper integrates:

- historical finite-field representation mathematics;
- exact verification of slide-derived identities;
- the reproducible Java TMTO experiments;
- the initial Rust reference implementation;
- the Java/Rust equivalence roadmap;
- open research questions for a future IACR ePrint submission.

Build locally with two LaTeX passes:

```bash
pdflatex -interaction=nonstopmode -halt-on-error -jobname=cryptanalytic-time-memory-tradeoffs main.tex
pdflatex -interaction=nonstopmode -halt-on-error -jobname=cryptanalytic-time-memory-tradeoffs main.tex
```
