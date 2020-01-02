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

#include <sys/cdefs.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <err.h>
#include <ripemd.h>
#include <skein.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/*
 *
 */
#include "sha_test.h"

/*
 * Length of test block, number of test blocks.
 */
#define TEST_BLOCK_LEN 10000
#define TEST_BLOCK_COUNT 100000
#define MDTESTCOUNT 8

static int qflag;
static int rflag;
static int sflag;
static char* checkAgainst;
static int checksFailed;

typedef void (DIGEST_Init)(void *);
typedef void (DIGEST_Update)(void *, const unsigned char *, size_t);
typedef char *(DIGEST_End)(void *, char *);

extern const char *SHA384_TestOutput[MDTESTCOUNT];
extern const char *SHA512_TestOutput[MDTESTCOUNT];
extern const char *SHA512t256_TestOutput[MDTESTCOUNT];
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

extern char *SHA512_32End(SHA512_32CTX *, char *);
extern char *SHA512_32Fd(int, char *);
extern char *SHA512_32FdChunk(int, char *, off_t, off_t);
extern char *SHA512_32File(const char *, char *);
extern char *SHA512_32FileChunk(const char *, char *, off_t, off_t);
extern char *SHA512_32Data (const void *, unsigned int, char *);


typedef union {
	SHA512_32CTX sha512;
} DIGEST_CTX;

/* max(SHA_DIGEST_LENGTH, SHA256_DIGEST_LENGTH, SHA512_DIGEST_LENGTH)*2+1 */

#define HEX_DIGEST_LENGTH 257

/* algorithm function table */

static const struct Algorithm_t Algorithm[] = {
	{ "sha512", "SHA512", &SHA512_TestOutput, (DIGEST_Init*)&SHA512_Init,
		(DIGEST_Update*)&SHA512_Update, (DIGEST_End*)&SHA512_End,
		&SHA512_Data, &SHA512_File },
	{ "sha384", "SHA384", &SHA384_TestOutput, (DIGEST_Init*)&SHA384_Init,
		(DIGEST_Update*)&SHA384_Update, (DIGEST_End*)&SHA384_End,
		&SHA384_Data, &SHA384_File },
        /*------ 32 bit implementation ----------*/
	{ "sha384_32", "SHA384_32", &SHA384_TestOutput, (DIGEST_Init*)&SHA384_32Init,
		(DIGEST_Update*)&SHA384_32Update, (DIGEST_End*)&SHA384_32End,
		&SHA384_32Data, &SHA384_32File },
	{ "sha512_32", "SHA512_32", &SHA512_TestOutput, (DIGEST_Init*)&SHA512_32Init,
		(DIGEST_Update*)&SHA512_32Update, (DIGEST_End*)&SHA512_32End,
		&SHA512_32Data, &SHA512_32File }
};


/* Main driver.

Arguments (may be any combination):
  -h(?)    - usage
  -sstring - digests string
  -t       - runs time trial
  -x       - runs test script
  filename - digests file
  (none)   - digests standard input
 */

int
main(int argc, char *argv[])
{
	int	ch;
	char   *p;
	char	buf[HEX_DIGEST_LENGTH];
	int	failed;
 	unsigned	digest;
 	const char*	progname;

 	if ((progname = strrchr(argv[0], '/')) == NULL)
 		progname = argv[0];
 	else
 		progname++;

 	for (digest = 0; digest < sizeof(Algorithm)/sizeof(*Algorithm); digest++)
 		if (strcasecmp(Algorithm[digest].progname, progname) == 0)
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
				warn("%s", *argv);
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
		printf("%s \"%s\"", buf, string);
	else
		printf("%s (\"%s\") = %s", alg->name, string, buf);
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
static void
MDTimeTrial(const Algorithm_t *alg)
{
	DIGEST_CTX context;
	struct rusage before, after;
	struct timeval total;
	float seconds;
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
	getrusage(RUSAGE_SELF, &before);

	/* Digest blocks */
	alg->Init(&context);
	for (i = 0; i < TEST_BLOCK_COUNT; i++)
		 alg->Update(&context, block, TEST_BLOCK_LEN);
	p = alg->End(&context, buf);
        p = buf;

	/* Stop timer */
	getrusage(RUSAGE_SELF, &after);
	timersub(&after.ru_utime, &before.ru_utime, &total);
	seconds = total.tv_sec + (float) total.tv_usec / 1000000;

	printf(" done\n");
	printf("Digest = %s", p);
	printf("\nTime = %f seconds\n", seconds);
	printf("Speed = %f MiB/second\n", (float) TEST_BLOCK_LEN * 
		(float) TEST_BLOCK_COUNT / seconds / (1 << 20));
}


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
that its security is in some doubt"
};


const char *SHA1_TestOutput[MDTESTCOUNT] = {
	"da39a3ee5e6b4b0d3255bfef95601890afd80709",
	"86f7e437faa5a7fce15d1ddcb9eaeaea377667b8",
	"a9993e364706816aba3e25717850c26c9cd0d89d",
	"c12252ceda8be8994d5fa0290a47231c1d16aae3",
	"32d10c7b8cf96570ca04ce37f2a19d84240d3a89",
	"761c457bf73b14d27e9e9265c46f4b4dda11f940",
	"50abf5706a150990a08b2c5ea40fa0e585554732",
	"18eca4333979c4181199b7b4fab8786d16cf2846"
};

const char *SHA256_TestOutput[MDTESTCOUNT] = {
	"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
	"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
	"f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650",
	"71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73",
	"db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0",
	"f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e",
	"e6eae09f10ad4122a0e2a4075761d185a272ebd9f5aa489e998ff2f09cbfdd9f"
};

const char *SHA384_TestOutput[MDTESTCOUNT] = {
	"38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
	"54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31",
	"cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
	"473ed35167ec1f5d8e550368a3db39be54639f828868e9454c239fc8b52e3c61dbd0d8b4de1390c256dcbb5d5fd99cd5",
	"feb67349df3db6f5924815d6c3dc133f091809213731fe5c7b5f4999e463479ff2877f5f2936fa63bb43784b12f3ebb4",
	"1761336e3f7cbfe51deb137f026f89e01a448e3b1fafa64039c1464ee8732f11a5341a6f41e0c202294736ed64db1a84",
	"b12932b0627d1c060942f5447764155655bd4da0c9afa6dd9b9ef53129af1b8fb0195996d2de9ca0df9d821ffee67026",
	"99428d401bf4abcd4ee0695248c9858b7503853acfae21a9cffa7855f46d1395ef38596fcd06d5a8c32d41a839cc5dfb"
};

const char *SHA512_TestOutput[MDTESTCOUNT] = {
	"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
	"1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75",
	"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
	"107dbf389d9e9f71a3a95f6c055b9251bc5268c2be16d6c13492ea45b0199f3309e16455ab1e96118e8a905d5597b72038ddb372a89826046de66687bb420e7c",
	"4dbff86cc2ca1bae1e16468a05cb9881c97f1753bce3619034898faa1aabe429955a1bf8ec483d7421fe3c1646613a59ed5441fb0f321389f77f48a879c7b1f1",
	"1e07be23c26a86ea37ea810c8ec7809352515a970e9253c26f536cfc7a9996c45c8370583e0a78fa4a90041d71a4ceab7423f19c71b9d5a3e01249f0bebd5894",
	"72ec1ef1124a45b047e8b7c75a932195135bb61de24ec0d1914042246e0aec3a2354e093d76f3048b456764346900cb130d2a4fd5dd16abb5e30bcb850dee843",
	"e8a835195e039708b13d9131e025f4441dbdc521ce625f245a436dcd762f54bf5cb298d96235e6c6a304e087ec8189b9512cbdf6427737ea82793460c367b9c3"
};


static void
MDTestSuite(const Algorithm_t *alg)
{
	int i;
	char buffer[HEX_DIGEST_LENGTH];

	printf("%s test suite:\n", alg->name);
	for (i = 0; i < MDTESTCOUNT; i++) {
		(*alg->Data)(MDTestInput[i], strlen(MDTestInput[i]), buffer);
		printf("%s (\"%s\") = %s", alg->name, MDTestInput[i], buffer);
		if (strcmp(buffer, (*alg->TestOutput)[i]) == 0)
			printf(" - verified correct\n");
		else
			printf(" - INCORRECT RESULT!\n");
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
			err(1, "stdout");
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
