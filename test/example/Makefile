.PHONY: all

all:
	FUZZ_INTROSPECTOR=1 ${CC} -fsanitize=fuzzer -fuse-ld=gold -flto -g main.c -o main.out
	${CC} -fprofile-instr-generate -fcoverage-mapping -fsanitize=fuzzer -g main.c -o main.out

clean:
	rm -rf fuzzerLogFile* *.profraw *.out tmp/
