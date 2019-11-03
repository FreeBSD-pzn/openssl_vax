It is a project to porting OpenSSL 1.1.1a to the 32 bit system.

The goal of this project rewrite all modules
which include 64 bit implementation to the 32 bit implementation.

To release this project is using FreeBSD with it development system.

Files in the directory:
config_out.txt           - output from configdata.pm OpenSSL 1.1.1a
exclude_files.txt        - the list of excluded files while compile on a VAX,
                           which include 64 bit implementation and need to
                           rewrite
steps.txt                 - the list of made steps
list_of_dir.txt           - simple list of directories in original package OpenSSL 1.1.1a
list_of_files.txt         - simple list of files in original package OpenSSL 1.1.1a

The first step is CRYPTO/SHA directory.

The main idea is create an union like this:

typedef union {           /* # define SHA_LONG32 unsigned int */
   unsigned int  i[2];
   unsigned long l;
   } SHA_LONG32;

which will be use to test with original 64 bit implementation by unsigned long value (l).
