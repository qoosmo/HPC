PDF=cryptanalytic-time-memory-tradeoffs

.PHONY: all clean

all:
	pdflatex -interaction=nonstopmode -halt-on-error -jobname=$(PDF) main.tex
	pdflatex -interaction=nonstopmode -halt-on-error -jobname=$(PDF) main.tex

clean:
	rm -f *.aux *.log *.out *.toc *.fdb_latexmk *.fls *.synctex.gz
