#---------------------------------------------
#
#
#
CC := cc
CFLAGS := -c -Wall
LINK := cc
LFLAGS :=
LIBS :=

SHA_TEST := mem_clr.o sha512_32.o sha512_32hl.o  sha512.o sha512hl.o sha_test.o

SHA512 := sha512.o sha512hl.o

SHA512_32 := sha512_32.o sha512_32.o

CLEARFILES := *.o sha512hl.c sha512_32hl.c sha_test sha512 sha512_32

.c.o:
	$(CC) $(CFLAGS) $*.c

all: sha_test sha512 sha512_32

#sha512: $(SHA512)
#	$(LINK) -o sha512 $(SHA512)

#sha512_32: $(SHA512_32)
#	$(LINK) -o sha512_32 $(SHA512_32)

sha_test: $(SHA_TEST)
	$(LINK) -o sha_test $(SHA_TEST)

clear:
	rm $(CLEARFILES)

#---------------------------------------------------------------
sha512_32hl.c: mdXhl.c
	(echo '#define LENGTH 64'; \
		sed -e 's/mdX/sha512_32/g' -e 's/MDX/SHA512_32/g' \
		-e 's/SHA512__32/SHA512_32/g'  \
		-e 's/_CTX/CTX/g' ${.ALLSRC}) > ${.TARGET}	

sha512hl.c: mdXhl.c
	(echo '#define LENGTH 64'; \
		sed -e 's/mdX/sha512/g' -e 's/MDX/SHA512_/g' -e 's/SHA512__/SHA512_/g' \
		${.ALLSRC}) > ${.TARGET}

#
sha_test.o: sha_test.h sha512.c sha512_32.c sha_test.c mem_clr.c
sha512.o: sha512.c sha_test.h
sha512_32.o: sha512_32.c sha_test.h
mem_clr.o: mem_clr.c

#---------------------------------------------------------------
