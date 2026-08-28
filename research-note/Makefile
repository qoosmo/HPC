PDF=cryptanalytic-time-memory-tradeoffs.pdf

all: $(PDF)

$(PDF): main.tex
	latexmk -pdf -interaction=nonstopmode -halt-on-error -jobname=cryptanalytic-time-memory-tradeoffs main.tex

clean:
	latexmk -C -jobname=cryptanalytic-time-memory-tradeoffs main.tex
