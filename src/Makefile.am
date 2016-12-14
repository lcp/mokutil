bin_PROGRAMS    = mokutil svlist

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

svlist_CFLAGS   = $(EFIVAR_CFLAGS)	\
		  $(OPENSSL_CFLAGS)	\
		  $(WARNINGFLAGS_C)

svlist_LDADD    = $(EFIVAR_LIBS)	\
		  $(OPENSSL_LIBS)

svlist_SOURCES  = svlist.h 		\
		  svlist.c
