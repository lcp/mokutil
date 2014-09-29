bin_PROGRAMS    = mokutil

mokutil_CFLAGS  = $(OPENSSL_CFLAGS)	\
		  $(EFIVAR_CFLAGS)	\
		  $(WARNINGFLAGS_C)

mokutil_LDADD   = $(OPENSSL_LIBS)	\
		  $(EFIVAR_LIBS)	\
		  -lcrypt

mokutil_SOURCES = signature.h \
		  password-crypt.h \
		  password-crypt.c \
		  mokutil.c
