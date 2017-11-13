bin_PROGRAMS    = mokutil mokutil-gtk

mokutil_CFLAGS  = $(OPENSSL_CFLAGS)	\
		  $(EFIVAR_CFLAGS)	\
		  $(WARNINGFLAGS_C)

mokutil_LDADD   = $(OPENSSL_LIBS)	\
		  $(EFIVAR_LIBS)	\
		  -lcrypt

mokutil_SOURCES = signature.h \
		  utils.h \
		  password-crypt.h \
		  password-crypt.c \
		  utils.c \
		  mokutil.c

mokutil_gtk_CFLAGS  = $(OPENSSL_CFLAGS)	\
		      $(EFIVAR_CFLAGS)	\
		      $(GTK3_CFLAGS)	\
		      $(WARNINGFLAGS_C)

mokutil_gtk_LDADD   = $(OPENSSL_LIBS)	\
		      $(EFIVAR_LIBS)	\
		      $(GTK3_LIBS)	\
		      -lcrypt

mokutil_gtk_SOURCES = signature.h \
		      utils.h \
		      password-crypt.h \
		      password-crypt.c \
		      utils.c \
		      mokutil-gtk.c
