/*
 * Derived from:
 *
 * MDDRIVER.C - test driver for MD2, MD4 and MD5
 */

/*
 *  Copyright (C) 1990-2, RSA Data Security, Inc. Created 1990. All
 *  rights reserved.
 *
 *  RSA Data Security, Inc. makes no representations concerning either
 *  the merchantability of this software or the suitability of this
 *  software for any particular purpose. It is provided "as is"
 *  without express or implied warranty of any kind.
 *
 *  These notices must be retained in any copies of any part of this
 *  documentation and/or software.
 */
#include "config.h"

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>

#ifndef OpenVMS
#include <sys/cdefs.h>
#include <ripemd.h>
#include <skein.h>
#include "sha512.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
/*
 *
 */

#include "sha512_32.h"

/*
 * Length of test block, number of test blocks.
 */
#define TEST_BLOCK_LEN 10000
#ifdef OpenVMS
#define TEST_BLOCK_COUNT 1000
#else
#define TEST_BLOCK_COUNT 10000
#endif
#define MDTESTCOUNT 9

static int qflag;
static int rflag;
static int sflag;
static char* checkAgainst;
static int checksFailed;
/*
 * To remove err.h and replace err() and warn()
 * functions variable progname has been
 * declare as a global variable.
 */
const char *progname;

typedef void (DIGEST_Init)(void *);
typedef void (DIGEST_Update)(void *, const unsigned char *, size_t);
typedef char *(DIGEST_End)(void *, char *);

extern const char *SHA384_TestOutput[MDTESTCOUNT];
extern const char *SHA512_TestOutput[MDTESTCOUNT];
extern const char *SHA512t256_TestOutput[MDTESTCOUNT];
extern const char *SHA512t224_TestOutput[MDTESTCOUNT];
/*------ 32 bit implementation the same as 64 bit ----------*/

typedef struct Algorithm_t {
	const char *progname;
	const char *name;
	const char *(*TestOutput)[MDTESTCOUNT];
	DIGEST_Init *Init;
	DIGEST_Update *Update;
	DIGEST_End *End;
	char *(*Data)(const void *, unsigned int, char *);
	char *(*File)(const char *, char *);
} Algorithm_t;



static void MDString(const Algorithm_t *, const char *);
static void MDTimeTrial(const Algorithm_t *);
static void MDTestSuite(const Algorithm_t *);
static void MDFilter(const Algorithm_t *, int);
static void usage(const Algorithm_t *);


typedef union {
	SHA512_32CTX sha512;
} DIGEST_CTX;

/* max(SHA_DIGEST_LENGTH, SHA256_DIGEST_LENGTH, SHA512_DIGEST_LENGTH)*2+1 */

#define HEX_DIGEST_LENGTH 257

/* algorithm function table */

static const struct Algorithm_t Algorithm[] = {
#ifndef THIRTY_TWO_BIT
	{ "sha512", "SHA512", &SHA512_TestOutput, (DIGEST_Init*)&SHA512_Init,
		(DIGEST_Update*)&SHA512_Update, (DIGEST_End*)&SHA512_End,
		&SHA512_Data, &SHA512_File },
	{ "sha384", "SHA384", &SHA384_TestOutput, (DIGEST_Init*)&SHA384_Init,
		(DIGEST_Update*)&SHA384_Update, (DIGEST_End*)&SHA384_End,
		&SHA384_Data, &SHA384_File },
	{ "sha512t224", "SHA512t224", &SHA512t224_TestOutput,
		(DIGEST_Init*)&SHA512_224_Init,
		(DIGEST_Update*)&SHA512_Update, (DIGEST_End*)&SHA512t224_End,
		&SHA512t224_Data, &SHA512t224_File },
	{ "sha512t256", "SHA512t256", &SHA512t256_TestOutput,
		(DIGEST_Init*)&SHA512_256_Init,
		(DIGEST_Update*)&SHA512_Update, (DIGEST_End*)&SHA512t256_End,
		&SHA512t256_Data, &SHA512t256_File },
#endif
        /*------ 32 bit implementation ----------*/
	{ "sha384_32", "SHA384_32", &SHA384_TestOutput, (DIGEST_Init*)&SHA384_32Init,
		(DIGEST_Update*)&SHA384_32Update, (DIGEST_End*)&SHA384_32End,
		&SHA384_32Data, &SHA384_32File },
	{ "sha512_32", "SHA512_32", &SHA512_TestOutput, (DIGEST_Init*)&SHA512_32Init,
		(DIGEST_Update*)&SHA512_32Update, (DIGEST_End*)&SHA512_32End,
		&SHA512_32Data, &SHA512_32File },
	{ "sha512t224_32", "SHA512T224_32", &SHA512t224_TestOutput,
		(DIGEST_Init*)&SHA512_224_32Init,
		(DIGEST_Update*)&SHA512_32Update, (DIGEST_End*)&SHA512t224_32End,
		&SHA512t224_32Data, &SHA512t224_32File },
	{ "sha512t256_32", "SHA512T256_32", &SHA512t256_TestOutput,
		(DIGEST_Init*)&SHA512_256_32Init,
		(DIGEST_Update*)&SHA512_32Update, (DIGEST_End*)&SHA512t256_32End,
		&SHA512t256_32Data, &SHA512t256_32File }
};


/* Main driver.

Arguments (may be any combination):
  -h(?)     - usage
  -s string - digests string
  -t        - runs time trial
  -x        - runs test script
  filename  - digests file
  (none)    - digests standard input
 */

int
main(int argc, char *argv[])
{
	int	ch;
	char   *p;
	char	buf[HEX_DIGEST_LENGTH];
	int	failed;
 	unsigned	digest;
        int     len;
        /* move variable progname to the global        
 	const char*	progname;
        */
#ifdef OpenVMS
        char   cmp = ']';
#else
        char   cmp = '/';
#endif

 	if ((progname = strrchr(argv[0], cmp )) == NULL)
 		progname = argv[0];
 	else
 		progname++;

        /* Executable file in the OpenVMS has extention - .EXE;n,
         * in *NIXes operating systems executable file might
         * without .exe extention.
         * Windows operating system also has .EXE extention,
         * so, to choice Algorithm 
         * strcasecmp() has been replaced on a
         * strncasecmp().
         */
        /* To get a N in the strncasecmp()
         * find a position ".exe" in the progname
         */
        len = strlen( progname );
        p   = strstr( progname, ".exe" );
        if( p )  len -= strlen( p );
        p   = strstr( progname, ".EXE" );
        if( p )  len -= strlen( p );
        
 	for (digest = 0; digest < sizeof(Algorithm)/sizeof(*Algorithm); digest++)
 		if ( strncasecmp( Algorithm[digest].progname, progname, len ) == 0)
 			break;

 	if (digest == sizeof(Algorithm)/sizeof(*Algorithm))
 		digest = 0;

	failed = 0;
	checkAgainst = NULL;
	checksFailed = 0;
	while ((ch = getopt(argc, argv, "?hc:pqrs:tx")) != -1)
		switch (ch) {
		case 'c':
			checkAgainst = optarg;
			break;
		case 'p':
			MDFilter(&Algorithm[digest], 1);
			break;
		case 'q':
			qflag = 1;
			break;
		case 'r':
			rflag = 1;
			break;
		case 's':
			sflag = 1;
			MDString(&Algorithm[digest], optarg);
			break;
		case 't':
			MDTimeTrial(&Algorithm[digest]);
			break;
		case 'x':
			MDTestSuite(&Algorithm[digest]);
			break;
		case '?':
                case 'h':
		default:
			usage(&Algorithm[digest]);
		}
	argc -= optind;
	argv += optind;

	if (*argv) {
		do {
			p = Algorithm[digest].File(*argv, buf);
			if (!p) {
				/* warn("%s", *argv);
                                 * replace on a frintf(stderr, ...)
                                 * to exclude err.h
                                 * 
                                 * print: name of program, argv
                                 * and number of error
                                 */
                                fprintf( stderr, "%s: %s. Error: [%d]\n",
                                         progname, *argv, errno );
				failed++;
			} else {
				if (qflag)
					printf("%s", p);
				else if (rflag)
					printf("%s %s", p, *argv);
				else
					printf("%s (%s) = %s",
					    Algorithm[digest].name, *argv, p);
				if (checkAgainst && strcasecmp(checkAgainst, p) != 0)
				{
					checksFailed++;
					if (!qflag)
						printf(" [ Failed ]");
				}
				printf("\n");
			}
		} while (*++argv);
	} else if (!sflag && (optind == 1 || qflag || rflag))
		MDFilter(&Algorithm[digest], 0);

	if (failed != 0)
		return (1);
	if (checksFailed != 0)
		return (2);

	return (0);
}


/*
 * Digests a string and prints the result.
 */
static void
MDString(const Algorithm_t *alg, const char *string)
{
	size_t len = strlen(string);
	char buf[HEX_DIGEST_LENGTH];

	alg->Data(string,len,buf);
	if (qflag)
		printf("%s", buf);
	else if (rflag)
		printf("%s\n\"%s\"", buf, string);
	else
		printf("%s (\"%s\") =\n%s", alg->name, string, buf);
	if (checkAgainst && strcasecmp(buf,checkAgainst) != 0)
	{
		checksFailed++;
		if (!qflag)
			printf(" [ failed ]");
	}
	printf("\n");
}



/*
 * Measures the time to digest TEST_BLOCK_COUNT TEST_BLOCK_LEN-byte blocks.
 */
#ifdef OpenVMS
/*-----------------------------
 * VMS dependent HEADER files
 *-----------------------------*/
#include <descrip.h>           /* Defined data types in DECC      */
#include <SMG$ROUTINES.H>      /* Defined function SMG            */
#include <SMGDEF.H>            /* Defined data types & keyboard   */
#include <SMGMSG.H>            /* Defined messages from functions */
#include <SSDEF.H>             /* Defined messages SS$_xx         */
#include <LIBDEF.H>            /* Defined messages LIB$_xx        */
#include <LIB$ROUTINES.H>      /* Defined lib$ routines           */
#endif

static void
MDTimeTrial(const Algorithm_t *alg)
{
	DIGEST_CTX context;
#ifdef  OpenVMS
        unsigned long status;
        unsigned long stime, cputime;
        long          code=2;
#endif
#ifndef OpenVMS
	struct rusage before, after;
#endif
	struct timeval total;
	float speed, seconds;
	unsigned char block[TEST_BLOCK_LEN];
	unsigned int i;
	char *p, buf[HEX_DIGEST_LENGTH];

	printf("%s time trial. Digesting %d %d-byte blocks ...",
	    alg->name, TEST_BLOCK_COUNT, TEST_BLOCK_LEN);
	fflush(stdout);

	/* Initialize block */
	for (i = 0; i < TEST_BLOCK_LEN; i++)
		block[i] = (unsigned char) (i & 0xff);

	/* Start timer */
#ifdef  OpenVMS
        status = lib$init_timer( &stime );
#endif
#ifndef OpenVMS
	getrusage(RUSAGE_SELF, &before);
#endif

	/* Digest blocks */
	alg->Init(&context);
	for (i = 0; i < TEST_BLOCK_COUNT; i++)
		 alg->Update(&context, block, TEST_BLOCK_LEN);
	p = alg->End(&context, buf);
        p = buf;

	/* Stop timer */
#ifdef  OpenVMS
        status = lib$stat_timer( &code, &cputime, &stime );
        seconds = (float) cputime;
        seconds /=100;
#endif
#ifndef OpenVMS
	getrusage(RUSAGE_SELF, &after);
	timersub(&after.ru_utime, &before.ru_utime, &total);
	seconds = total.tv_sec + (float) total.tv_usec / 1000000;
#endif
	printf(" done\n");
	printf("Digest = %s\n", p);
	printf("\nTime = %f seconds\n", seconds);
        if( seconds != 0 )
          {
            speed = (float) TEST_BLOCK_LEN * (float) TEST_BLOCK_COUNT / seconds;
            if( speed > 1000000 )   
               printf("Speed = %f MiB/second\n", speed / (1 << 20));
            else
               printf("Speed = %f KiB/second\n", speed / (1 << 10));
          }

}    /* End of MDTimeTrial() */



/*
 * Digests a reference suite of strings and prints the results.
 */

static const char *MDTestInput[MDTESTCOUNT] = {
	"",
	"a",
	"abc",
	"message digest",
	"abcdefghijklmnopqrstuvwxyz",
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
	"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
	"MD5 has not yet (2001-09-03) been broken, but sufficient attacks have been made \
that its security is in some doubt",
	"The quick brown fox jumps over the lazy dog"
};


const char *SHA1_TestOutput[MDTESTCOUNT] = {
	"da39a3ee5e6b4b0d3255bfef95601890afd80709",
	"86f7e437faa5a7fce15d1ddcb9eaeaea377667b8",
	"a9993e364706816aba3e25717850c26c9cd0d89d",
	"c12252ceda8be8994d5fa0290a47231c1d16aae3",
	"32d10c7b8cf96570ca04ce37f2a19d84240d3a89",
	"761c457bf73b14d27e9e9265c46f4b4dda11f940",
	"50abf5706a150990a08b2c5ea40fa0e585554732",
	"18eca4333979c4181199b7b4fab8786d16cf2846",
	"2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
};

const char *SHA256_TestOutput[MDTESTCOUNT] = {
	"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
	"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
	"f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650",
	"71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73",
	"db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0",
	"f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e",
	"e6eae09f10ad4122a0e2a4075761d185a272ebd9f5aa489e998ff2f09cbfdd9f",
	"d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
};

const char *SHA384_TestOutput[MDTESTCOUNT] = {
	"38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
	"54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31",
	"cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
	"473ed35167ec1f5d8e550368a3db39be54639f828868e9454c239fc8b52e3c61dbd0d8b4de1390c256dcbb5d5fd99cd5",
	"feb67349df3db6f5924815d6c3dc133f091809213731fe5c7b5f4999e463479ff2877f5f2936fa63bb43784b12f3ebb4",
	"1761336e3f7cbfe51deb137f026f89e01a448e3b1fafa64039c1464ee8732f11a5341a6f41e0c202294736ed64db1a84",
	"b12932b0627d1c060942f5447764155655bd4da0c9afa6dd9b9ef53129af1b8fb0195996d2de9ca0df9d821ffee67026",
	"99428d401bf4abcd4ee0695248c9858b7503853acfae21a9cffa7855f46d1395ef38596fcd06d5a8c32d41a839cc5dfb",
	"ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1"
};

const char *SHA512_TestOutput[MDTESTCOUNT] = {
	"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
	"1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75",
	"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
	"107dbf389d9e9f71a3a95f6c055b9251bc5268c2be16d6c13492ea45b0199f3309e16455ab1e96118e8a905d5597b72038ddb372a89826046de66687bb420e7c",
	"4dbff86cc2ca1bae1e16468a05cb9881c97f1753bce3619034898faa1aabe429955a1bf8ec483d7421fe3c1646613a59ed5441fb0f321389f77f48a879c7b1f1",
	"1e07be23c26a86ea37ea810c8ec7809352515a970e9253c26f536cfc7a9996c45c8370583e0a78fa4a90041d71a4ceab7423f19c71b9d5a3e01249f0bebd5894",
	"72ec1ef1124a45b047e8b7c75a932195135bb61de24ec0d1914042246e0aec3a2354e093d76f3048b456764346900cb130d2a4fd5dd16abb5e30bcb850dee843",
	"e8a835195e039708b13d9131e025f4441dbdc521ce625f245a436dcd762f54bf5cb298d96235e6c6a304e087ec8189b9512cbdf6427737ea82793460c367b9c3",
	"07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6"
};

const char *SHA512t256_TestOutput[MDTESTCOUNT] = {
	"c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
	"455e518824bc0601f9fb858ff5c37d417d67c2f8e0df2babe4808858aea830f8",
	"53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
	"0cf471fd17ed69d990daf3433c89b16d63dec1bb9cb42a6094604ee5d7b4e9fb",
	"fc3189443f9c268f626aea08a756abe7b726b05f701cb08222312ccfd6710a26",
	"cdf1cc0effe26ecc0c13758f7b4a48e000615df241284185c39eb05d355bb9c8",
	"2c9fdbc0c90bdd87612ee8455474f9044850241dc105b1e8b94b8ddf5fac9148",
	"dd095fc859b336c30a52548b3dc59fcc0d1be8616ebcf3368fad23107db2d736",
	"dd9d67b371519c339ed8dbd25af90e976a1eeefd4ad3d889005e532fc5bef04d",
};

const char *SHA512t224_TestOutput[MDTESTCOUNT] = {
	"6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4",
	"d5cdb9ccc769a5121d4175f2bfdd13d6310e0d3d361ea75d82108327",
	"4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa",
	"ad1a4db188fe57064f4f24609d2a83cd0afb9b398eb2fcaeaae2c564",
	"ff83148aa07ec30655c1b40aff86141c0215fe2a54f767d3f38743d8",
	"a8b4b9174b99ffc67d6f49be9981587b96441051e16e6dd036b140d3",
	"ae988faaa47e401a45f704d1272d99702458fea2ddc6582827556dd2",
	"b3c3b945249b0c8c94aba76ea887bcaad5401665a1fbeb384af4d06b",
	"944cd2847fb54558d4775db0485a50003111c8e5daa63fe722c6aa37"
};


static void
MDTestSuite(const Algorithm_t *alg)
{
	int i;
	char buffer[HEX_DIGEST_LENGTH];

	printf("%s test suite:\n", alg->name);
	for (i = 0; i < MDTESTCOUNT; i++) {
		(*alg->Data)(MDTestInput[i], strlen(MDTestInput[i]), buffer);
		printf("%s\n\t(\"%s\") =>\n\t%s", alg->name, MDTestInput[i], buffer);
		if (strcmp(buffer, (*alg->TestOutput)[i]) == 0)
			printf("\n - verified correct\n");
		else
			printf("\n - INCORRECT RESULT!\n");
	}
}


/*
 * Digests the standard input and prints the result.
 */
static void
MDFilter(const Algorithm_t *alg, int tee)
{
	DIGEST_CTX context;
	unsigned int len;
	unsigned char buffer[BUFSIZ];
	char buf[HEX_DIGEST_LENGTH];

	alg->Init(&context);
	while ((len = fread(buffer, 1, BUFSIZ, stdin))) {
		if (tee && len != fwrite(buffer, 1, len, stdout))
                    {
                       /*
                        * Replace err() on a frintf(stderr,...)
                        * function to remove err.h
			err(1, "stdout");
                        *
                        * print: name of program, number of error
                        * and exit with 1.
                        */
                        fprintf( stderr, "%s: stdout. Error: %d\n",
                                 progname, errno );
                        exit(1);
                    }
		alg->Update(&context, buffer, len);
	}
	printf("%s\n", alg->End(&context, buf));
}


static void
usage(const Algorithm_t *alg)
{

	fprintf(stderr, "For help %s -h(?)\n", alg->progname);
	fprintf(stderr, "usage: %s [-pqrtx] [-c string] [-s string] [files ...]\n", alg->progname);
	exit(1);
}
