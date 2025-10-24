.PHONY: all

all:
	clang -S -emit-llvm -O0 -g main.c
	opt -passes=dot-callgraph main.ll > /dev/null

clean:
	rm main.ll *.dot .*.dot
