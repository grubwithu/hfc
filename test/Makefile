.PHONY: all

all:
	${CC} -c -g -fsanitize=fuzzer-no-link main.c -o main.a

clean:
	rm -f main.ll *.dot .*.dot
