$! Makefile.com
$! Compile 32bit release of sha
$ write sys$output "Remove OLDER versions .OBJ and .EXE files..."
$ delete *.obj;*
$ delete *.exe;*
$!--------------------------------------------------------------------------------------------------------
$! Compile sources files
$ write sys$output "Compile SOURCES files..."
$ cc /define="OpenVMS"    mem_clr.c
$ cc /define="OpenVMS"    sha384_32hl.c
$ cc /define="OpenVMS"    sha512_32hl.c
$ cc /define="OpenVMS"    sha512t224_32hl.c
$ cc /define="OpenVMS"    sha512t256_32hl.c
$ cc /define="OpenVMS"/object=SHA512_C_32   sha512_32.c
$ cc /define="OpenVMS"/object=sha512t224_32 md5.c
$ cc /define="OpenVMS"/object=sha512t256_32 md5.c
$ cc /define="OpenVMS"/object=sha384_32     md5.c
$ cc /define="OpenVMS"/object=sha512_32     md5.c
$!--------------------------------------------------------------------------------------------------------
$! Has been added sha1, sha224, sha256
$ cc /define="OpenVMS"    sha1dgst.c
$ cc /define="OpenVMS"    sha1_one.c
$ cc /define="OpenVMS"/object=SHA256_C    sha256.c
$ cc /define="OpenVMS"    sha1hl.c
$ cc /define="OpenVMS"    sha224hl.c
$ cc /define="OpenVMS"    sha256hl.c
$ cc /define="OpenVMS"/object=sha1   md5.c
$ cc /define="OpenVMS"/object=sha224 md5.c
$ cc /define="OpenVMS"/object=sha256 md5.c
$!--------------------------------------------------------------------------------------------------------
$! link executable files: sha384_32.exe, sha512_32.exe, sha512t224_32.exe, sha512t256_32.exe
$!--------------------------------------------------------------------------------------------------------
$ write sys$output "Linking EXECUTABLE files..."
$ link sha384_32.obj,     MEM_CLR, SHA512_C_32, SHA384_32HL, SHA512_32HL, SHA512T224_32HL, SHA512T256_32HL, SHA1DGST, SHA1_ONE, SHA256_C, SHA1HL, SHA224HL, SHA256HL
$ link sha512_32.obj,     MEM_CLR, SHA512_C_32, SHA384_32HL, SHA512_32HL, SHA512T224_32HL, SHA512T256_32HL, SHA1DGST, SHA1_ONE, SHA256_C, SHA1HL, SHA224HL, SHA256HL
$ link sha512t224_32.obj, MEM_CLR, SHA512_C_32, SHA384_32HL, SHA512_32HL, SHA512T224_32HL, SHA512T256_32HL, SHA1DGST, SHA1_ONE, SHA256_C, SHA1HL, SHA224HL, SHA256HL
$ link sha512t256_32.obj, MEM_CLR, SHA512_C_32, SHA384_32HL, SHA512_32HL, SHA512T224_32HL, SHA512T256_32HL, SHA1DGST, SHA1_ONE, SHA256_C, SHA1HL, SHA224HL, SHA256HL
$!--------------------------------------------------------------------------------------------------------
$! Has been added sha1, sha224, sha256
$ link sha1.obj,          MEM_CLR, SHA512_C_32, SHA384_32HL, SHA512_32HL, SHA512T224_32HL, SHA512T256_32HL, SHA1DGST, SHA1_ONE, SHA256_C, SHA1HL, SHA224HL, SHA256HL
$ link sha224.obj,        MEM_CLR, SHA512_C_32, SHA384_32HL, SHA512_32HL, SHA512T224_32HL, SHA512T256_32HL, SHA1DGST, SHA1_ONE, SHA256_C, SHA1HL, SHA224HL, SHA256HL
$ link sha256.obj,        MEM_CLR, SHA512_C_32, SHA384_32HL, SHA512_32HL, SHA512T224_32HL, SHA512T256_32HL, SHA1DGST, SHA1_ONE, SHA256_C, SHA1HL, SHA224HL, SHA256HL
$!--------------------------------------------------------------------------------------------------------
$! End of makefile.com
$!--------------------
