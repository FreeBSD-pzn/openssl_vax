#---------------------------------------------
#
#
#
CC := cc
CFLAGS := -c -Wall
LINK := cc
LFLAGS :=
LIBS :=

SHA_TEST := mem_clr.o sha512_32.o sha512_32hl.o  sha512.o sha512hl.o sha384_32hl.o sha_test.o

SHA512 := mem_clr.o sha512.o sha512hl.o sha512_32.o sha512_32hl.o sha384hl.o \
		sha384_32hl.o sha512t256_32hl.o sha512t224_32hl.o md5.o

SHA512_32 := mem_clr.o sha512.o sha512hl.o sha512_32.o sha512_32hl.o sha384hl.o \
		sha384_32hl.o sha512t256_32hl.o sha512t224_32hl.o md5.o

SHA512T256_32 := mem_clr.o sha512.o sha512hl.o sha512_32.o sha512_32hl.o sha384hl.o \
		sha384_32hl.o sha512t256_32hl.o sha512t224_32hl.o md5.o

SHA512T224_32 := mem_clr.o sha512.o sha512hl.o sha512_32.o sha512_32hl.o sha384hl.o \
		sha384_32hl.o sha512t256_32hl.o sha512t224_32hl.o md5.o

SHA384 := mem_clr.o sha512.o sha512hl.o sha512_32.o sha512_32hl.o sha384hl.o \
		sha384_32hl.o sha512t256_32hl.o sha512t224_32hl.o md5.o

SHA384_32 := mem_clr.o sha512.o sha512hl.o sha512_32.o sha512_32hl.o sha384hl.o \
		sha384_32hl.o sha512t256_32hl.o sha512t224_32hl.o md5.o

CLEARFILES := *.o sha512hl.c sha512_32hl.c sha384hl.c sha384_32hl.c \
		sha512t256_32hl.c sha512t224_32hl.c \
		sha_test sha512 sha512_32 sha384 sha384_32 sha512t256_32 sha512t224_32

.c.o:
	$(CC) $(CFLAGS) $*.c

all: sha_test sha512 sha512_32 sha512t256_32 sha512t224_32 sha384_32 sha384

sha512: $(SHA512)
	$(LINK) -o sha512 $(SHA512)

sha512_32: $(SHA512_32)
	$(LINK) -o sha512_32 $(SHA512_32)

sha512t256_32: $(SHA512T256_32)
	$(LINK) -o sha512t256_32 $(SHA512T256_32)

sha512t224_32: $(SHA512T224_32)
	$(LINK) -o sha512t224_32 $(SHA512T224_32)

sha384: $(SHA384)
	$(LINK) -o sha384 $(SHA384)

sha384_32: $(SHA384_32)
	$(LINK) -o sha384_32 $(SHA384_32)

sha_test: $(SHA_TEST)
	$(LINK) -o sha_test $(SHA_TEST)

clean:
	rm $(CLEARFILES)

#---------------------------------------------------------------
sha384hl.c: mdXhl.c
	(echo '#define LENGTH 48'; \
		sed -e 's/mdX/sha384/g' -e 's/MDX/SHA384_/g'	\
		-e 's/SHA384__/SHA384_/g'  \
                -e 's/SHA384_CTX/SHA512_CTX/g' ${.ALLSRC}) > ${.TARGET}

sha384_32hl.c: mdXhl.c
	(echo '#define LENGTH 48'; \
		sed -e 's/mdX/sha384_32/g' -e 's/MDX/SHA384_32/g'	\
		-e 's/SHA384__32/SHA384_32/g'  \
		-e 's/_CTX/CTX/g' \
                -e 's/SHA384_32CTX/SHA512_32CTX/g' ${.ALLSRC}) > ${.TARGET}

sha512_32hl.c: mdXhl.c
	(echo '#define LENGTH 64'; \
		sed -e 's/mdX/sha512_32/g' -e 's/MDX/SHA512_32/g' \
		-e 's/SHA512__32/SHA512_32/g'  \
		-e 's/_CTX/CTX/g' ${.ALLSRC}) > ${.TARGET}	

sha512hl.c: mdXhl.c
	(echo '#define LENGTH 64'; \
		sed -e 's/mdX/sha512/g' -e 's/MDX/SHA512_/g' -e 's/SHA512__/SHA512_/g' \
		${.ALLSRC}) > ${.TARGET}

sha512t256_32hl.c: mdXhl.c
	(echo '#define LENGTH 32'; \
	sed -e 's/mdX/sha512t256_32/g' -e 's/MDX/SHA512t256_32/g' -e 's/SHA512t256__32/SHA512t256_32/g'  \
	-e 's/SHA512t256_32Init/SHA512_256_32Init/g' \
	-e 's/SHA512t256_32Update/SHA512_32Update/g' \
	-e 's/SHA512t256_32Final/SHA512_32Final/g' \
	-e 's/SHA512t256_32_CTX/SHA512_32CTX/g' ${.ALLSRC}) > ${.TARGET}

sha512t224_32hl.c: mdXhl.c
	(echo '#define LENGTH 28'; \
	sed -e 's/mdX/sha512t224_32/g' -e 's/MDX/SHA512t224_32/g' -e 's/SHA512t224__32/SHA512t224_32/g'  \
	-e 's/SHA512t224_32Init/SHA512_224_32Init/g' \
	-e 's/SHA512t224_32Update/SHA512_32Update/g' \
	-e 's/SHA512t224_32Final/SHA512_32Final/g' \
	-e 's/SHA512t224_32_CTX/SHA512_32CTX/g' ${.ALLSRC}) > ${.TARGET}


#
sha_test.o: sha_test.h sha512.c sha512_32.c sha_test.c mem_clr.c
sha512.o: sha512.c sha_test.h
sha512_32.o: sha512_32.c sha_test.h
sha384hl.o: sha384hl.c sha_test.h
sha384_32hl.o: sha384_32hl.c sha_test.h
sha512t256_32hl.o: sha512t256_32hl.c sha_test.h
sha512t224_32hl.o: sha512t224_32hl.c sha_test.h
mem_clr.o: mem_clr.c
#---------------------------------------------------------------
