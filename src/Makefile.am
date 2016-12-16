bin_PROGRAMS    = mokutil sblist

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

sblist_CFLAGS   = $(EFIVAR_CFLAGS)	\
		  $(OPENSSL_CFLAGS)	\
		  $(WARNINGFLAGS_C)

sblist_LDADD    = $(EFIVAR_LIBS)	\
		  $(OPENSSL_LIBS)

sblist_SOURCES  = sbversion.h 		\
		  sblist.c
