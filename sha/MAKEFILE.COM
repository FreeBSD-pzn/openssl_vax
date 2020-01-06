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
$! link executable files: sha384_32.exe, sha512_32.exe, sha512t224_32.exe, sha512t256_32.exe
$!--------------------------------------------------------------------------------------------------------
$ write sys$output "Linking EXECUTABLE files..."
$ link sha384_32.obj,     MEM_CLR, SHA512_C_32, SHA384_32HL, SHA512_32HL, SHA512T224_32HL, SHA512T256_32HL
$ link sha512_32.obj,     MEM_CLR, SHA512_C_32, SHA384_32HL, SHA512_32HL, SHA512T224_32HL, SHA512T256_32HL
$ link sha512t224_32.obj, MEM_CLR, SHA512_C_32, SHA384_32HL, SHA512_32HL, SHA512T224_32HL, SHA512T256_32HL
$ link sha512t256_32.obj, MEM_CLR, SHA512_C_32, SHA384_32HL, SHA512_32HL, SHA512T224_32HL, SHA512T256_32HL
$!--------------------
$! End of makefile.com
$!--------------------
