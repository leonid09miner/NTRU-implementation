
all: ntru

clean: 
	@rm -rf ntru

ntru: main.cpp sha256.c 
	g++ -o ntru main.cpp sha256.c -lsodium

