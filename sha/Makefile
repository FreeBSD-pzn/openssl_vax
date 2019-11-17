#---------------------------------------------
#
#
#
CC := cc
CFLAGS := -c -Wall
LINK := cc
LFLAGS :=
LIBS :=

SHA_TEST := mem_clr.o sha512.o sha512_32.o sha512_32_end.o sha_test.o 

.c.o:
	$(CC) $(CFLAGS) $*.c

all: sha_test

sha_test: $(SHA_TEST)
	$(LINK) -o sha_test $(SHA_TEST)

#---------------------------------------------------------------
sha_test.o: sha_test.h sha512.c sha512_32.c sha512_32_end.c sha_test.c mem_clr.c
sha512.o: sha512.c sha_test.h
sha512_32.o: sha512_32.c sha_test.h
sha512_32_end.o: sha512_32_end.c sha_test.h
mem_clr.o: mem_clr.c
#---------------------------------------------------------------
