all:
	clang38 -o chmailpass -O3 -std=c99 -pedantic -I/usr/local/include -L/usr/local/lib -lsqlite3 -lcrypt chmailpass.c

install:
	install -s -g wheel -o root -m 4511 chmailpass /usr/local/bin

clean:
	rm -f chmailpass
