.PHONY: all

all:
	$(CC) -o client.out cJSON.h interface.c cJSON.c -lcurl

run: all
	./client.out
