bin_PROGRAMS    = mokutil

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

if GTK
bin_PROGRAMS	+= mokutil-gtk

mokutil_gtk_CFLAGS  = $(OPENSSL_CFLAGS)	\
		      $(EFIVAR_CFLAGS)	\
		      $(GTK3_CFLAGS)	\
		      -DLOCALEDIR='"$(localedir)"' \
		      $(WARNINGFLAGS_C)

mokutil_gtk_LDADD   = $(OPENSSL_LIBS)	\
		      $(EFIVAR_LIBS)	\
		      $(GTK3_LIBS)	\
		      -lcrypt

mokutil_gtk_SOURCES = signature.h \
		      utils.h \
		      utils-gtk.h \
		      password-crypt.h \
		      password-crypt.c \
		      utils-gtk.c \
		      utils.c \
		      mokutil-gtk.c
endif
