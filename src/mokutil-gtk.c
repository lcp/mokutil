#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <efivar.h>

#include <glib/gi18n.h>
#include <gtk/gtk.h>

#include <openssl/sha.h>
#include <openssl/x509.h>

#include "utils.h"

typedef enum {
	MOK = 0,
	MOK_NEW,
	MOK_DEL,
	MOKX,
	MOKX_NEW,
	MOKX_DEL,
	DB,
	DBX,
	NUM_OF_VARS
} MOKVar;

static const char *
mokvar_to_string[NUM_OF_VARS] = {
	"MokListRT",
	"MokNew",
	"MokDel",
	"MokListXRT",
	"MokXNew",
	"MokXDel",
	"db",
	"dbx",
};

static const efi_guid_t *
var_guid[NUM_OF_VARS] = {
	&efi_guid_shim,
	&efi_guid_shim,
	&efi_guid_shim,
	&efi_guid_shim,
	&efi_guid_shim,
	&efi_guid_shim,
	&efi_guid_security,
	&efi_guid_security,
};

GtkWidget *mokpage[NUM_OF_VARS];
uint8_t *var_data[NUM_OF_VARS];
size_t var_size[NUM_OF_VARS];

static char *
get_x509_time_str (ASN1_TIME *time)
{
	BIO *bio = BIO_new (BIO_s_mem());
	char *time_str;

	ASN1_TIME_print (bio, time);
	time_str = (char *)calloc (bio->num_write + 1, 1);
	if (time_str == NULL)
		return NULL;
	BIO_read (bio, time_str, bio->num_write);
	BIO_free (bio);

	return time_str;
}

static const char *
get_x509_name_str (X509_NAME *X509name, int nid)
{
	X509_NAME_ENTRY *cn_entry = NULL;
	ASN1_STRING *cn_asn1 = NULL;
	int cn_loc = -1;

	cn_loc = X509_NAME_get_index_by_NID (X509name, nid, -1);
	if (cn_loc < 0)
		return NULL;

	cn_entry = X509_NAME_get_entry (X509name, cn_loc);
	if (cn_entry == NULL)
		return NULL;

	cn_asn1 = X509_NAME_ENTRY_get_data (cn_entry);
	if (cn_asn1 == NULL)
		return NULL;

	return (char *)ASN1_STRING_data (cn_asn1);;
}

static const char *
get_x509_common_name (X509 *X509cert)
{
	return get_x509_name_str (X509_get_subject_name (X509cert),
				  NID_commonName);
}

static char *
get_x509_serial_str (X509 *X509cert)
{
	ASN1_INTEGER *serial;
	BIGNUM *bnser;
	unsigned char hexbuf[30];
	int i, n;
	char *serial_str, *ptr;

	serial = X509_get_serialNumber(X509cert);
	if (serial == NULL)
		return NULL;

	bnser = ASN1_INTEGER_to_BN(serial, NULL);
	n = BN_bn2bin(bnser, hexbuf);
	serial_str = (char *)calloc (n*3 + 1, 1);
	if (serial_str == NULL)
		return NULL;

	ptr = serial_str;
	for (i = 0; i < n; i++) {
		sprintf (serial_str, "%02x", hexbuf[i]);
		ptr += 2;
		if (i < n-1) {
			sprintf (ptr, ":");
			ptr++;
		}
	}

	return serial_str;
}

/* For the key page tree view */
enum {
	TYPE_COLUMN,
	KEY_COLUMN,
	N_COLUMNS
};

static void
append_fingerprint (const char *cert, const int cert_size,
		    GtkTreeStore *store, GtkTreeIter *p_iter,
		    GtkTreeIter *c_iter)
{
	SHA_CTX ctx_sha1;
	SHA256_CTX ctx_sha256;
	uint8_t sha1[SHA_DIGEST_LENGTH];
	uint8_t sha256[SHA256_DIGEST_LENGTH];
	char output[SHA256_DIGEST_LENGTH * 3];
	char *ptr;

	/* Fingerprint (title) */
	gtk_tree_store_append (store, c_iter, p_iter);
	gtk_tree_store_set (store, c_iter, TYPE_COLUMN, _("Fingerprint:"), -1);

	/* SHA1 fingerprint */
	SHA1_Init (&ctx_sha1);
	SHA1_Update (&ctx_sha1, cert, cert_size);
	SHA1_Final (sha1, &ctx_sha1);

	ptr = output;
	for (unsigned int i = 0; i < SHA_DIGEST_LENGTH; i++) {
		sprintf (ptr, "%02x", sha1[i]);
		ptr += 2;
		if (i < SHA_DIGEST_LENGTH - 1) {
			sprintf (ptr, ":");
			ptr++;
		}
	}

	gtk_tree_store_append (store, c_iter, p_iter);
	gtk_tree_store_set (store, c_iter, TYPE_COLUMN, _("SHA1"), -1);
	gtk_tree_store_set (store, c_iter, KEY_COLUMN, output, -1);

	/* SHA256 fingerprint */
	SHA256_Init (&ctx_sha256);
	SHA256_Update (&ctx_sha256, cert, cert_size);
	SHA256_Final (sha256, &ctx_sha256);

	ptr = output;
	for (unsigned int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		sprintf (ptr, "%02x", sha256[i]);
		ptr += 2;
		if (i == (SHA256_DIGEST_LENGTH / 2) - 1) {
			sprintf (ptr, "\n");
			ptr++;
		} else if (i < SHA256_DIGEST_LENGTH - 1) {
			sprintf (ptr, ":");
			ptr++;
		}
	}

	gtk_tree_store_append (store, c_iter, p_iter);
	gtk_tree_store_set (store, c_iter, TYPE_COLUMN, _("SHA256"), -1);
	gtk_tree_store_set (store, c_iter, KEY_COLUMN, output, -1);
}

static void
append_time_entry (ASN1_TIME *time, const char *name,
		   GtkTreeStore *store, GtkTreeIter *p_iter,
		   GtkTreeIter *c_iter)
{
	char *str;

	str = get_x509_time_str (time);
	gtk_tree_store_append (store, c_iter, p_iter);
	gtk_tree_store_set (store, c_iter, TYPE_COLUMN, name,
			    KEY_COLUMN, str, -1);
	free (str);
}

typedef struct {
	int nid;
	const char *name;
} NidName;

static NidName nidname[] = {
	{NID_commonName, "Name"},
	{NID_organizationName, "Organization"},
	{NID_countryName, "Country"},
	{NID_stateOrProvinceName, "State"},
	{NID_localityName, "Locality"},
	{-1, NULL}
};

static void
append_name_entries (X509_NAME *X509name, GtkTreeStore *store,
		     GtkTreeIter *p_iter, GtkTreeIter *c_iter)
{
	const char *str;
	int i;

	for (i = 0; nidname[i].name != NULL; i++) {
		str = get_x509_name_str (X509name, nidname[i].nid);
		if (str != NULL) {
			gtk_tree_store_append (store, c_iter, p_iter);
			gtk_tree_store_set (store, c_iter,
					    TYPE_COLUMN, _(nidname[i].name),
					    KEY_COLUMN, str, -1);
		}
	}
}

static void
append_cert_entries (MokListNode *node, X509 *X509cert, GtkTreeStore *store,
		     GtkTreeIter *p_iter, GtkTreeIter *c_iter)
{
	X509_NAME *X509name;
	char *str;

	/* Serial Number */
	str = get_x509_serial_str (X509cert);
	gtk_tree_store_append (store, c_iter, p_iter);
	/* TODO markup bold */
	gtk_tree_store_set (store, c_iter, TYPE_COLUMN, _("Serial:"), -1);
	free (str);

	gtk_tree_store_append (store, c_iter, p_iter);
	gtk_tree_store_set (store, c_iter, TYPE_COLUMN, NULL,
			    KEY_COLUMN, NULL, -1);

	/* Subject (title) */
	gtk_tree_store_append (store, c_iter, p_iter);
	gtk_tree_store_set (store, c_iter, TYPE_COLUMN, _("Subject:"), -1);

	X509name = X509_get_subject_name (X509cert);

	append_name_entries (X509name, store, p_iter, c_iter);

	gtk_tree_store_append (store, c_iter, p_iter);
	gtk_tree_store_set (store, c_iter, -1);

	/* Issuer (title) */
	gtk_tree_store_append (store, c_iter, p_iter);
	gtk_tree_store_set (store, c_iter, TYPE_COLUMN, _("Issuer:"), -1);

	X509name = X509_get_issuer_name (X509cert);

	append_name_entries (X509name, store, p_iter, c_iter);

	gtk_tree_store_append (store, c_iter, p_iter);
	gtk_tree_store_set (store, c_iter, -1);

	/* Valid Date */
	gtk_tree_store_append (store, c_iter, p_iter);
	gtk_tree_store_set (store, c_iter, TYPE_COLUMN, _("Valid Date:"), -1);

	append_time_entry (X509_get_notBefore (X509cert), _("From"),
			   store, p_iter, c_iter);

	append_time_entry (X509_get_notAfter (X509cert), _("Until"),
			   store, p_iter, c_iter);

	gtk_tree_store_append (store, c_iter, p_iter);
	gtk_tree_store_set (store, c_iter, -1);

	/* Fingerprint */
	append_fingerprint (node->mok, node->mok_size, store, p_iter, c_iter);
}

static void
append_cert (GtkTreeStore *store, MokListNode *node)
{
	GtkTreeIter p_iter, c_iter;
	X509 *X509cert;
	BIO *cert_bio;
	const char *common_name;

	if (node == NULL)
		return;

	/* Set the treeview */
	gtk_tree_store_append (store, &p_iter, NULL);
	gtk_tree_store_set (store, &p_iter, TYPE_COLUMN, "X509", -1);

	/* Convert DER to X509 structure */
	cert_bio = BIO_new (BIO_s_mem());
	if (cert_bio == NULL) {
		fprintf (stderr, "Failed to allocate BIO\n");
		return;
	}
	BIO_write (cert_bio, node->mok, node->mok_size);
	X509cert = d2i_X509_bio (cert_bio, NULL);
	if (X509cert == NULL) {
		gtk_tree_store_set (store, &p_iter, KEY_COLUMN,
				    _("Invalid certificate"), -1);
		return;
	}

	/* Set the key column to the common name */
	common_name = get_x509_common_name (X509cert);
	gtk_tree_store_set (store, &p_iter, KEY_COLUMN, common_name, -1);

	/* Append the contents of the certificate to the child nodes */
	append_cert_entries (node, X509cert, store, &p_iter, &c_iter);
}

static void
append_hash_entries (MokListNode *node, GtkTreeStore *store,
		     GtkTreeIter *p_iter)
{
	GtkTreeIter c_iter;
	uint32_t hash_size, sig_size, remain;
	uint32_t i;
	uint8_t *hash;
	char str[SHA512_DIGEST_LENGTH * 2 + 1];
	char *ptr;

	hash_size = efi_hash_size (&node->header->SignatureType);
	sig_size = hash_size + sizeof(efi_guid_t);

	remain = node->mok_size;
	hash = (uint8_t *)node->mok;

	while (remain > 0) {
		if (remain < sig_size) {
			fprintf (stderr, "invalid array size\n");
			return;
		}

		hash += sizeof(efi_guid_t);

		ptr = str;
		for (i = 0; i < hash_size; i++) {
			sprintf (ptr, "%02x", hash[i]);
			ptr += 2;
		}
		gtk_tree_store_append (store, &c_iter, p_iter);
		gtk_tree_store_set (store, &c_iter, KEY_COLUMN, str, -1);

		hash += hash_size;
		remain -= sig_size;
	}
}

static void
append_hash (GtkTreeStore *store, MokListNode *node)
{
	GtkTreeIter iter;
	char *name;

	if (node == NULL)
		return;

	int rc = efi_guid_to_name(&node->header->SignatureType, &name);
	if (rc < 0 || isxdigit(name[0])) {
		if (name) {
			free(name);
			fprintf (stderr, "unknown hash type: %s\n", name);
		} else {
			fprintf (stderr, "unknown hash type\n");
		}
		return;
	}

	/* We only accept SHA family for now */
	if (strncmp ("SHA", name, 3) != 0)
		return;

	gtk_tree_store_append (store, &iter, NULL);
	gtk_tree_store_set (store, &iter, TYPE_COLUMN, name, -1);
	free (name);

	append_hash_entries (node, store, &iter);
}

static GtkWidget *
create_mok_page (MOKVar id)
{
	GtkWidget *page;
	GtkWidget *treeview;
	GtkTreeStore *store;
	GtkCellRenderer *renderer;
	GtkTreeViewColumn *column;
	MokListNode *list = NULL;
	uint32_t moknum;

	if (var_data[id] == NULL) {
		/* Exclude the empty MOK requests */
		if (id == MOK_NEW  || id == MOK_DEL ||
		    id == MOKX_NEW || id == MOKX_DEL)
			return NULL;
		page = gtk_label_new (_("empty"));
		goto out;
	}

	list = build_mok_list (var_data[id], var_size[id], &moknum);
	if (list == NULL) {
		page = gtk_label_new (_("empty"));
		goto out;
	}

	page = gtk_scrolled_window_new (NULL, NULL);

	store = gtk_tree_store_new(N_COLUMNS, G_TYPE_STRING, G_TYPE_STRING);
	treeview = gtk_tree_view_new_with_model (GTK_TREE_MODEL (store));
	g_object_unref (G_OBJECT (store));

	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes (_("Type"), renderer,
							   "text", TYPE_COLUMN,
							   NULL);
	gtk_tree_view_append_column (GTK_TREE_VIEW (treeview), column);

	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes (_("Key"), renderer,
							   "text", KEY_COLUMN,
							   NULL);
	gtk_tree_view_append_column (GTK_TREE_VIEW (treeview), column);

	/* Iterate the list and create the treeview items */
	for (unsigned int i = 0; i < moknum; i++) {
		if (efi_guid_cmp (&list[i].header->SignatureType,
				  &efi_guid_x509_cert) == 0) {
			append_cert (store, &list[i]);
		} else {
			append_hash (store, &list[i]);
		}
	}

	gtk_container_add (GTK_CONTAINER(page), treeview);
	gtk_scrolled_window_set_min_content_width (GTK_SCROLLED_WINDOW(page),
						   600);
	gtk_scrolled_window_set_min_content_height (GTK_SCROLLED_WINDOW(page),
						    400);

out:
	mokpage[id] = page;
	if (list)
		free (list);
	return page;
}

static int
generate_pages (GtkWidget *container)
{
	const char *var_name;
	uint32_t attributes;
	int ret;

	/* Iterate the MOK variables and initialize the related variables */
	for (int i = 0; i < NUM_OF_VARS; i++) {
		var_name = mokvar_to_string[i];
		var_data[i] = NULL;
		ret = efi_get_variable (*var_guid[i], var_name,
					&var_data[i], &var_size[i],
					&attributes);
		if (ret < 0)
			var_data[i] = NULL;

		GtkWidget *page_label = gtk_label_new (var_name);
		mokpage[i] = create_mok_page (i);
		if (mokpage[i] != NULL)
			gtk_notebook_append_page (GTK_NOTEBOOK(container),
						  mokpage[i], page_label);
	}

	return 0;
}

static void
show_ui(void)
{
	GtkWidget *window, *vbox;
	GtkWidget *menu_bar, *pages;

	window = gtk_window_new (GTK_WINDOW_TOPLEVEL);
	/* TODO free var_data on exit */
	g_signal_connect (window, "destroy",
		          G_CALLBACK (gtk_main_quit), NULL);
	gtk_window_set_title (GTK_WINDOW(window), "mokutil");

	vbox = gtk_box_new (GTK_ORIENTATION_VERTICAL, 5);
	gtk_container_add (GTK_CONTAINER(window), vbox);

	menu_bar = gtk_menu_bar_new ();
	gtk_box_pack_start (GTK_BOX(vbox), menu_bar, FALSE, FALSE, 0);
	/* TODO add menu items */

	pages = gtk_notebook_new ();
	gtk_box_pack_start (GTK_BOX(vbox), pages, FALSE, FALSE, 0);
	gtk_notebook_set_scrollable (GTK_NOTEBOOK(pages), TRUE);
	generate_pages (pages);

	gtk_widget_show_all (window);
}

int
main (int argc, char **argv)
{
#ifdef ENABLE_NLS
	bindtextdomain (GETTEXT_PACKAGE, PACKAGE_LOCALE_DIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);
#endif
	gtk_init (&argc, &argv);
	show_ui ();
	gtk_main ();

	return 0;
}
