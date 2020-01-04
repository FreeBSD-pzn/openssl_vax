#---------------------------------------------
#
#
#
CC := cc
CFLAGS := -c -Wall
LINK := cc
LFLAGS :=
LIBS :=

# sha_test is using to test all components of 32 bit implementation SHA:
# functions: &, |, ~, ^, ++, --, +, -
# defines: B(x,j), PULL64(x), ROTR(x,s), Sigma0(x), Sigma1(x), sigma0(x),
#          sigma1(x), Ch(x,y,z), Maj(x,y,z)
#--------------------------------------------
# To use it uncomment all lines with sha_test
#SHA_TEST := mem_clr.o sha512_32.o sha512_32hl.o sha512.o sha512hl.o sha384_32hl.o sha_test.o

SHA384 := mem_clr.o sha512.o sha384hl.o sha512hl.o sha512t256hl.o sha512t224hl.o \
		sha384_32hl.o sha512_32.o sha512_32hl.o sha512t256_32hl.o sha512t224_32hl.o md5.o

SHA512 := mem_clr.o sha512.o sha384hl.o sha512hl.o sha512t256hl.o sha512t224hl.o \
		sha384_32hl.o sha512_32.o sha512_32hl.o sha512t256_32hl.o sha512t224_32hl.o md5.o

SHA512T256 := mem_clr.o sha512.o sha384hl.o sha512hl.o sha512t256hl.o sha512t224hl.o \
		sha384_32hl.o sha512_32.o sha512_32hl.o sha512t256_32hl.o sha512t224_32hl.o md5.o

SHA512T224 := mem_clr.o sha512.o sha384hl.o sha512hl.o sha512t256hl.o sha512t224hl.o \
		sha384_32hl.o sha512_32.o sha512_32hl.o sha512t256_32hl.o sha512t224_32hl.o md5.o

SHA384_32 := mem_clr.o sha512.o sha384hl.o sha512hl.o sha512t256hl.o sha512t224hl.o \
		sha384_32hl.o sha512_32.o sha512_32hl.o sha512t256_32hl.o sha512t224_32hl.o md5.o

SHA512_32 := mem_clr.o sha512.o sha384hl.o sha512hl.o sha512t256hl.o sha512t224hl.o \
		sha384_32hl.o sha512_32.o sha512_32hl.o sha512t256_32hl.o sha512t224_32hl.o md5.o

SHA512T256_32 := mem_clr.o sha512.o sha384hl.o sha512hl.o sha512t256hl.o sha512t224hl.o \
		sha384_32hl.o sha512_32.o sha512_32hl.o sha512t256_32hl.o sha512t224_32hl.o md5.o

SHA512T224_32 := mem_clr.o sha512.o sha384hl.o sha512hl.o sha512t256hl.o sha512t224hl.o \
		sha384_32hl.o sha512_32.o sha512_32hl.o sha512t256_32hl.o sha512t224_32hl.o md5.o

CLEARFILES := *.o sha384hl.c sha512hl.c sha512t256hl.c sha512t224hl.c \
		sha384_32hl.c sha512_32hl.c sha512t256_32hl.c sha512t224_32hl.c \
		sha384 sha512 sha512t256 sha512t224 \
		sha384_32 sha512_32 sha512t256_32 sha512t224_32

.c.o:
	$(CC) $(CFLAGS) $*.c

all:	sha384 sha512 sha512t256 sha512t224 \
	sha384_32 sha512_32 sha512t256_32 sha512t224_32

sha384: $(SHA384)
	$(LINK) -o sha384 $(SHA384)

sha512: $(SHA512)
	$(LINK) -o sha512 $(SHA512)

sha512t256: $(SHA512T256)
	$(LINK) -o sha512t256 $(SHA512T256)

sha512t224: $(SHA512T224)
	$(LINK) -o sha512t224 $(SHA512T224)

sha384_32: $(SHA384_32)
	$(LINK) -o sha384_32 $(SHA384_32)

sha512_32: $(SHA512_32)
	$(LINK) -o sha512_32 $(SHA512_32)

sha512t256_32: $(SHA512T256_32)
	$(LINK) -o sha512t256_32 $(SHA512T256_32)

sha512t224_32: $(SHA512T224_32)
	$(LINK) -o sha512t224_32 $(SHA512T224_32)

#sha_test: $(SHA_TEST)
#	$(LINK) -o sha_test $(SHA_TEST)

clean:
	rm $(CLEARFILES)

#---------------------------------------------------------------
sha384hl.c: mdXhl.c
	(echo '#define LENGTH 48'; \
		sed -e 's/mdX/sha384/g' -e 's/MDX/SHA384_/g'	\
		-e 's/SHA384__/SHA384_/g'  \
                -e 's/SHA384_CTX/SHA512_CTX/g' ${.ALLSRC}) > ${.TARGET}

sha512hl.c: mdXhl.c
	(echo '#define LENGTH 64'; \
		sed -e 's/mdX/sha512/g' -e 's/MDX/SHA512_/g' -e 's/SHA512__/SHA512_/g' \
		${.ALLSRC}) > ${.TARGET}

sha512t256hl.c: mdXhl.c
	(echo '#define LENGTH 32'; \
	sed -e 's/mdX/sha512t256/g' -e 's/MDX/SHA512t256_/g' -e 's/SHA512t256__/SHA512t256_/g'  \
	-e 's/SHA512t256_Init/SHA512_256_Init/g' \
	-e 's/SHA512t256_Update/SHA512_Update/g' \
	-e 's/SHA512t256_Final/SHA512_Final/g' \
	-e 's/SHA512t256_CTX/SHA512_CTX/g' ${.ALLSRC}) > ${.TARGET}

sha512t224hl.c: mdXhl.c
	(echo '#define LENGTH 28'; \
	sed -e 's/mdX/sha512t224/g' -e 's/MDX/SHA512t224_/g' -e 's/SHA512t224__/SHA512t224_/g'  \
	-e 's/SHA512t224_Init/SHA512_224_Init/g' \
	-e 's/SHA512t224_Update/SHA512_Update/g' \
	-e 's/SHA512t224_Final/SHA512_Final/g' \
	-e 's/SHA512t224_CTX/SHA512_CTX/g' ${.ALLSRC}) > ${.TARGET}

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
#sha_test.o: sha_test.h sha512.c sha512_32.c sha_test.c mem_clr.c
#------------------------------------------------------------------
# 64 bit implementation
sha384hl.o: sha384hl.c sha512_32.h
sha512.o: sha512.c sha512_32.h
sha512t256hl.o: sha512t256hl.c sha512_32.h
sha512t224hl.o: sha512t224hl.c sha512_32.h
#------------------------------------------------------------------
# 32 bit implementation
sha384_32hl.o: sha384_32hl.c sha512_32.h
sha512_32.o: sha512_32.c sha512_32.h
sha512t256_32hl.o: sha512t256_32hl.c sha512_32.h
sha512t224_32hl.o: sha512t224_32hl.c sha512_32.h
mem_clr.o: mem_clr.c
#---------------------------------------------------------------
