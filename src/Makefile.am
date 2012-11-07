bin_PROGRAMS    = mokutil

mokutil_CFLAGS  = $(OPENSSL_CFLAGS) \
		  $(WARNINGFLAGS_C)

mokutil_LDADD   = $(OPENSSL_LIBS)

mokutil_SOURCES = efi.h \
		  efilib.c \
		  signature.h \
		  mokutil.c
