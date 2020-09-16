bin_PROGRAMS    = mokutil

mokutil_CFLAGS  = $(OPENSSL_CFLAGS)	\
		  $(EFIVAR_CFLAGS)	\
		  $(LIBKEYUTILS_CFLAGS)	\
		  $(WARNINGFLAGS_C)	\
		  -DVERSION="\"$(VERSION)\""

mokutil_LDADD   = $(OPENSSL_LIBS)	\
		  $(EFIVAR_LIBS)	\
		  $(LIBKEYUTILS_LIBS)	\
		  -lcrypt

mokutil_SOURCES = signature.h \
		  efi_hash.h \
		  efi_hash.c \
		  efi_x509.h \
		  efi_x509.c \
		  keyring.h \
		  keyring.c \
		  password-crypt.h \
		  password-crypt.c \
		  util.h \
		  util.c \
		  mokutil.h \
		  mokutil.c
