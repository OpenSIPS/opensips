LIBNAME=	digest_auth

include ../../Makefile.openssl

LIBS=

CPP_CMD?=cpp

SHA_256_SUPPORT:= $(shell bash -c "echo -e '\x23define SHA256_Init(x) \
	_TEST_P_A_S_S_E_D_()\n\x23include <openssl/sha.h>\n'" \
	| $(CPP_CMD) $(DEFS) 2>/dev/null | grep -q _TEST_P_A_S_S_E_D_ && echo yes)

SHA_512_256_SUPPORT:= $(shell bash -c "echo -e '\x23define EVP_sha512_256(x) \
	_TEST_P_A_S_S_E_D_()\n\x23include <openssl/evp.h>\n'" \
	| $(CPP_CMD) $(DEFS) 2>/dev/null | grep -q _TEST_P_A_S_S_E_D_ && echo yes)


ifeq ($(SHA_256_SUPPORT)$(SHA_256_SUPPORT_DISABLE),yes)
	DEFS+=-DSHA_256_ENABLE
else
	exclude_files+=$(wildcard *sha256.c)
endif

ifeq ($(SHA_512_256_SUPPORT)$(SHA_512_256_SUPPORT_DISABLE),yes)
	DEFS+=-DSHA_512_256_ENABLE
else
	exclude_files+=$(wildcard *sha512t256.c)
endif

include ../../Makefile.misclibs
