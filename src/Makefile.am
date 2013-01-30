bin_PROGRAMS    = mokutil

mokutil_CFLAGS  = $(OPENSSL_CFLAGS) \
		  $(WARNINGFLAGS_C)

mokutil_LDADD   = $(OPENSSL_LIBS) \
		  -lcrypt

mokutil_SOURCES = efi.h \
		  efilib.c \
		  signature.h \
		  password-crypt.h \
		  password-crypt.c \
		  mokutil.c
