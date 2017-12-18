#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>

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
	[MOK] = "MokListRT",
	[MOK_NEW] = "MokNew",
	[MOK_DEL] = "MokDel",
	[MOKX] = "MokListXRT",
	[MOKX_NEW] = "MokXNew",
	[MOKX_DEL] = "MokXDel",
	[DB] = "db",
	[DBX] = "dbx",
};

static const MOKVar
mokvar_id [NUM_OF_VARS] = {
	[MOK] = MOK,
	[MOK_NEW] = MOK_NEW,
	[MOK_DEL] = MOK_DEL,
	[MOKX] = MOKX,
	[MOKX_NEW] = MOKX_NEW,
	[MOKX_DEL] = MOKX_DEL,
	[DB] = DB,
	[DBX] = DBX,
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
MokListNode *list[NUM_OF_VARS];

static char *
get_x509_time_str (ASN1_TIME *time)
{
	BIO *bio = BIO_new (BIO_s_mem());
	char *time_str;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	uint64_t num_write;
#else
	unsigned long num_write;
#endif

	ASN1_TIME_print (bio, time);
	num_write = BIO_number_written (bio);
	time_str = (char *)calloc (num_write + 1, 1);
	if (time_str == NULL)
		return NULL;
	BIO_read (bio, time_str, num_write);
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

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	return (const char *)ASN1_STRING_get0_data (cn_asn1);
#else
	return (const char *)ASN1_STRING_data (cn_asn1);;
#endif
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

	serial = X509_get_serialNumber (X509cert);
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

static void
show_info_dialog (GtkWindow *window, const char *msg)
{
	GtkWidget *dialog;

	dialog = gtk_message_dialog_new (window,
					 GTK_DIALOG_DESTROY_WITH_PARENT,
					 GTK_MESSAGE_INFO,
					 GTK_BUTTONS_OK,
					 "%s", _("Information"));
	gtk_message_dialog_format_secondary_text (GTK_MESSAGE_DIALOG(dialog),
						  "%s", msg);

	gtk_dialog_run (GTK_DIALOG(dialog));
	gtk_widget_destroy (dialog);
}

static void
show_err_dialog (GtkWindow *window, const char *msg)
{
	GtkWidget *dialog;

	dialog = gtk_message_dialog_new (window,
					 GTK_DIALOG_DESTROY_WITH_PARENT,
					 GTK_MESSAGE_ERROR,
					 GTK_BUTTONS_OK,
					 "%s", _("Error"));
	gtk_message_dialog_format_secondary_text (GTK_MESSAGE_DIALOG(dialog),
						  "%s", msg);

	gtk_dialog_run (GTK_DIALOG(dialog));
	gtk_widget_destroy (dialog);
}


static void
root_check_cb (GtkToggleButton *toggle, GtkWidget *pwd_entry[])
{
	if (gtk_toggle_button_get_active (toggle)) {
		gtk_widget_set_sensitive (pwd_entry[0], FALSE);
		gtk_widget_set_sensitive (pwd_entry[1], FALSE);
	} else {
		gtk_widget_set_sensitive (pwd_entry[0], TRUE);
		gtk_widget_set_sensitive (pwd_entry[1], TRUE);
	}
}

static int
show_password_dialog (GtkWindow *window, char **password, gboolean *root_pw)
{
	GtkWidget *dialog, *content;
	GtkWidget *label, *root_check;
	GtkWidget *pwd_entry[2];
	GtkDialogFlags flags;
	gint result;
	const gchar *pwd1, *pwd2;

	*root_pw = FALSE;

	flags = GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT;
	dialog = gtk_dialog_new_with_buttons (_("Password"),
					      window,
					      flags,
					      _("_OK"),
					      GTK_RESPONSE_ACCEPT,
					      _("_Cancel"),
					      GTK_RESPONSE_CANCEL,
					      NULL);
	content = gtk_dialog_get_content_area (GTK_DIALOG(dialog));
	gtk_container_set_border_width (GTK_CONTAINER(content), 10);
	gtk_box_set_spacing (GTK_BOX(content), 10);

	label = gtk_label_new (_("Enter password for the request"));
	gtk_container_add (GTK_CONTAINER(content), label);

	pwd_entry[0] = gtk_entry_new ();
	gtk_entry_set_activates_default (GTK_ENTRY(pwd_entry[0]), TRUE);
	gtk_entry_set_visibility (GTK_ENTRY(pwd_entry[0]), FALSE);
	gtk_entry_set_input_purpose (GTK_ENTRY(pwd_entry[0]),
				     GTK_INPUT_PURPOSE_PASSWORD);
	gtk_container_add (GTK_CONTAINER(content), pwd_entry[0]);

	pwd_entry[1] = gtk_entry_new ();
	gtk_entry_set_activates_default (GTK_ENTRY(pwd_entry[1]), TRUE);
	gtk_entry_set_visibility (GTK_ENTRY(pwd_entry[1]), FALSE);
	gtk_entry_set_input_purpose (GTK_ENTRY(pwd_entry[1]),
				     GTK_INPUT_PURPOSE_PASSWORD);
	gtk_container_add (GTK_CONTAINER(content), pwd_entry[1]);

	root_check = gtk_check_button_new_with_label (_("Use root password"));
	g_signal_connect (root_check, "toggled", G_CALLBACK(root_check_cb),
			  pwd_entry);
	gtk_container_add (GTK_CONTAINER(content), root_check);

	gtk_widget_show_all (dialog);
again:
	result = gtk_dialog_run (GTK_DIALOG(dialog));
	if (result == GTK_RESPONSE_CANCEL) {
		gtk_widget_destroy (dialog);
		return -1;
	}

	*root_pw = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(root_check));
	if (*root_pw == TRUE)
		goto out;

	pwd1 = gtk_entry_get_text (GTK_ENTRY(pwd_entry[0]));
	pwd2 = gtk_entry_get_text (GTK_ENTRY(pwd_entry[1]));
	if (strcmp (pwd1, pwd2) != 0) {
		show_err_dialog (GTK_WINDOW(dialog),
				 _("Password doesn't match!"));
		goto again;
	}

	*password = g_strdup_printf ("%s", pwd1);
out:
	gtk_widget_destroy (dialog);
	return 0;
}

/* For the key page tree view */
enum {
	TYPE_COLUMN,
	TYPE_ALIGN_COLUMN,
	KEY_COLUMN,
	N_COLUMNS
};

static void
append_cert (GtkTreeStore *store, MokListNode *node)
{
	GtkTreeIter iter;
	X509 *X509cert;
	BIO *cert_bio;
	const char *common_name;

	if (node == NULL)
		return;

	/* Set the treeview */
	gtk_tree_store_append (store, &iter, NULL);
	gtk_tree_store_set (store, &iter, TYPE_COLUMN, "X509", -1);

	/* Convert DER to X509 structure */
	cert_bio = BIO_new (BIO_s_mem());
	if (cert_bio == NULL) {
		fprintf (stderr, "Failed to allocate BIO\n");
		return;
	}
	BIO_write (cert_bio, node->mok, node->mok_size);
	X509cert = d2i_X509_bio (cert_bio, NULL);
	if (X509cert == NULL) {
		gtk_tree_store_set (store, &iter, KEY_COLUMN,
				    _("Invalid certificate"), -1);
		return;
	}

	/* Set the key column to the common name */
	common_name = get_x509_common_name (X509cert);
	gtk_tree_store_set (store, &iter, KEY_COLUMN, common_name, -1);
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

static MOKVar cur_var_id;
static int cur_key_index;

static void
delete_key_cb (GtkMenuItem *menuitem __attribute__((unused)),
	       gpointer *data __attribute__((unused)))
{
	/* TODO delete the key */
	printf ("delete key %d from %s\n",
		cur_key_index,
		mokvar_to_string[cur_var_id]);
}

static void
add_cert_row (GtkWidget *grid, int row, const char *type_str, const char *str)
{
	GtkWidget *type, *key;

	if (type_str) {
		type = gtk_label_new (NULL);
		gtk_label_set_xalign (GTK_LABEL(type), 1.0);
		gtk_label_set_markup (GTK_LABEL(type), type_str);
		gtk_grid_attach (GTK_GRID(grid), type, 0, row, 1, 1);
	}

	if (str) {
		key = gtk_label_new (str);
		gtk_label_set_xalign (GTK_LABEL(key), 0.0);
		gtk_grid_attach (GTK_GRID(grid), key, 1, row, 1, 1);
	}
}

static void
add_fingerprint_entries (GtkWidget *grid, int *row, const uint8_t *cert,
			 const int cert_size)
{
	SHA_CTX ctx_sha1;
	SHA256_CTX ctx_sha256;
	uint8_t sha1[SHA_DIGEST_LENGTH];
	uint8_t sha256[SHA256_DIGEST_LENGTH];
	char output[SHA256_DIGEST_LENGTH * 3];
	char *ptr;

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

	add_cert_row (grid, (*row)++, _("SHA1"), output);

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

	add_cert_row (grid, (*row)++, _("SHA256"), output);
}

static void
add_time_entry (GtkWidget *grid, int *row, const char *name, ASN1_TIME *time)
{
	char *str;

	str = get_x509_time_str (time);
	add_cert_row (grid, (*row)++, name, str);
	if (str)
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
add_name_entries (GtkWidget *grid, X509_NAME *x509name, int *row)
{
	const char *str;
	int i;

	for (i = 0; nidname[i].name != NULL; i++) {
		str = get_x509_name_str (x509name, nidname[i].nid);
		if (str != NULL)
			add_cert_row (grid, (*row)++, nidname[i].name, str);
	}
}

static void
detail_cb (GtkMenuItem *menuitem __attribute__((unused)),
	   gpointer *data __attribute__((unused)))
{
	GtkWidget *dialog, *content, *grid;
	GtkDialogFlags flags;
	MokListNode *node;
	X509 *X509cert;
	X509_NAME *x509name;
	BIO *cert_bio;
	char *type_str, *str;
	int row_count;

	node = &list[cur_var_id][cur_key_index];

	/* Convert DER to X509 structure */
	cert_bio = BIO_new (BIO_s_mem());
	if (cert_bio == NULL) {
		fprintf (stderr, "%s: Failed to allocate BIO\n",
			 __FUNCTION__);
		return;
	}
	BIO_write (cert_bio, node->mok, node->mok_size);
	X509cert = d2i_X509_bio (cert_bio, NULL);
	if (X509cert == NULL) {
		fprintf (stderr, "%s: Invalid certificate\n",
			 __FUNCTION__);
		return;
	}

	/* Create the dialog window */
	flags = GTK_DIALOG_MODAL;
	/* TODO set the parent */
	dialog = gtk_dialog_new_with_buttons (_("Certificate Details"),
					      NULL, flags, _("OK"),
					      GTK_RESPONSE_ACCEPT, NULL);
	content = gtk_dialog_get_content_area (GTK_DIALOG(dialog));
	grid = gtk_grid_new ();
	gtk_container_add (GTK_CONTAINER(content), grid);
	gtk_grid_set_column_spacing (GTK_GRID(grid), 10);
	row_count = 0;

	/* Serial Number */
	type_str = g_strdup_printf ("<b>%s</b>", _("Serial:"));
	str = get_x509_serial_str (X509cert);
	add_cert_row (grid, row_count++, type_str, str);
	g_free (type_str);
	if (str)
		free (str);

	/* ==== */
	add_cert_row (grid, row_count++, " ", NULL);

	/* Subject */
	type_str = g_strdup_printf ("<b>%s</b>", _("Subject:"));
	add_cert_row (grid, row_count++, type_str, NULL);
	g_free (type_str);

	x509name = X509_get_subject_name (X509cert);
	add_name_entries (grid, x509name, &row_count);

	/* ==== */
	add_cert_row (grid, row_count++, " ", NULL);

	/* Issuer */
	type_str = g_strdup_printf ("<b>%s</b>", _("Issuer:"));
	add_cert_row (grid, row_count++, type_str, NULL);
	g_free (type_str);

	x509name = X509_get_issuer_name (X509cert);
	add_name_entries (grid, x509name, &row_count);

	/* ==== */
	add_cert_row (grid, row_count++, " ", NULL);

	/* Valid Date */
	type_str = g_strdup_printf ("<b>%s</b>", _("Valid Date:"));
	add_cert_row (grid, row_count++, type_str, NULL);

	add_time_entry (grid, &row_count, _("From"),
			X509_get_notBefore (X509cert));

	add_time_entry (grid, &row_count, _("Until"),
			X509_get_notAfter (X509cert));

	/* ==== */
	add_cert_row (grid, row_count++, " ", NULL);

	/* Fingerprint */
	type_str = g_strdup_printf ("<b>%s</b>", _("Fingerprint:"));
	add_cert_row (grid, row_count++, type_str, NULL);

	add_fingerprint_entries (grid, &row_count, node->mok, node->mok_size);

	gtk_widget_show_all (content);

	gtk_dialog_run (GTK_DIALOG(dialog));

	gtk_widget_destroy (dialog);
}

static gboolean
treeview_clicked (GtkTreeView *treeview, GdkEvent *event, MOKVar *id)
{
	GdkEventButton *button;
	GtkTreePath *path;
	GtkMenu *menu;
	GtkWidget *delete, *detail;
	char *path_str;

	if (event->type != GDK_BUTTON_PRESS)
		return FALSE;

	button = (GdkEventButton *)event;

	/* Catch the right-click */
	if (button->button != GDK_BUTTON_SECONDARY)
		return FALSE;

	gtk_tree_view_get_path_at_pos (treeview, button->x, button->y,
				       &path, NULL, NULL, NULL);

	if (!path || gtk_tree_path_get_depth(path) != 1)
		return FALSE;

	path_str = gtk_tree_path_to_string (path);
	if (!path_str)
		return FALSE;

	/* The depth of the path is 1, so we can convert the string
	 * directly */
	cur_key_index = atoi (path_str);
	g_free (path_str);

	cur_var_id = *id;

	/* Show the popup menu */
	menu = (GtkMenu *)gtk_menu_new ();
	delete = gtk_menu_item_new_with_label (_("Delete this key"));
	gtk_menu_attach (menu, delete, 0, 1, 0 ,1);
	g_signal_connect (G_OBJECT(delete), "activate",
			  G_CALLBACK(delete_key_cb), NULL);

	detail = gtk_menu_item_new_with_label (_("Details"));
	gtk_menu_attach (menu, detail, 0, 1, 1 ,2);
	g_signal_connect (G_OBJECT(detail), "activate",
			  G_CALLBACK(detail_cb), NULL);

	gtk_widget_show_all (GTK_WIDGET(menu));
	gtk_menu_popup_at_pointer (menu, event);

	return FALSE;
}

static GtkWidget *
create_mok_page (MOKVar id)
{
	GtkWidget *page;
	GtkWidget *treeview;
	GtkTreeStore *store;
	GtkCellRenderer *renderer;
	GtkTreeViewColumn *column;
	uint32_t moknum;

	if (var_data[id] == NULL) {
		page = gtk_label_new (_("empty"));
		return page;
	}

	list[id] = build_mok_list (var_data[id], var_size[id], &moknum);
	if (list[id] == NULL) {
		page = gtk_label_new (_("Failed to fetch the list."));
		gtk_widget_show (page);
		return page;
	}

	page = gtk_scrolled_window_new (NULL, NULL);

	store = gtk_tree_store_new(N_COLUMNS, G_TYPE_STRING, G_TYPE_FLOAT,
				   G_TYPE_STRING);
	treeview = gtk_tree_view_new_with_model (GTK_TREE_MODEL (store));
	g_object_unref (G_OBJECT (store));

	g_signal_connect (G_OBJECT(treeview), "button-press-event",
			  G_CALLBACK(treeview_clicked),
			  (gpointer)&mokvar_id[id]);

	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes (_("Type"), renderer,
						"markup", TYPE_COLUMN,
						"xalign", TYPE_ALIGN_COLUMN,
						NULL);
	gtk_tree_view_append_column (GTK_TREE_VIEW (treeview), column);

	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes (_("Key"), renderer,
							   "text", KEY_COLUMN,
							   NULL);
	gtk_tree_view_append_column (GTK_TREE_VIEW (treeview), column);

	/* Iterate the list and create the treeview items */
	for (unsigned int i = 0; i < moknum; i++) {
		if (efi_guid_cmp (&list[id][i].header->SignatureType,
				  &efi_guid_x509_cert) == 0) {
			append_cert (store, &list[id][i]);
		} else {
			append_hash (store, &list[id][i]);
		}
	}

	gtk_container_add (GTK_CONTAINER(page), treeview);
	gtk_scrolled_window_set_min_content_width (GTK_SCROLLED_WINDOW(page),
						   600);
	gtk_scrolled_window_set_min_content_height (GTK_SCROLLED_WINDOW(page),
						    400);

	gtk_widget_show_all (page);

	return page;
}

static inline void
update_tab (MOKVar id)
{
	/* Hide the empty MOK requests */
	if ((id == MOK_NEW  || id == MOK_DEL || id == MOKX_NEW ||
	     id == MOKX_DEL) && var_data[id] == NULL) {
		gtk_widget_hide (mokpage[id]);
	} else {
		gtk_widget_show_all (mokpage[id]);
	}
}

static int
generate_pages (GtkWidget *container)
{
	GtkWidget *page;
	const char *var_name;
	uint32_t attributes;
	int ret;

	/* Iterate the MOK variables and initialize the related variables */
	for (int i = 0; i < NUM_OF_VARS; i++) {
		list[i] = NULL;
		var_name = mokvar_to_string[i];
		var_data[i] = NULL;
		ret = efi_get_variable (*var_guid[i], var_name,
					&var_data[i], &var_size[i],
					&attributes);
		if (ret < 0)
			var_data[i] = NULL;

		GtkWidget *page_label = gtk_label_new (var_name);
		mokpage[i] = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
		page = create_mok_page (i);
		gtk_box_pack_start (GTK_BOX(mokpage[i]), page, TRUE, TRUE, 0);
		gtk_notebook_append_page (GTK_NOTEBOOK(container),
					  mokpage[i], page_label);
		update_tab (i);
	}

	return 0;
}

static void
destroy_children (GtkWidget *widget, gpointer data)
{
	GtkContainer *container;

	container = GTK_CONTAINER(data);

	gtk_container_remove (container, widget);
	gtk_widget_destroy (widget);
}

static void
refresh_page (MOKVar id)
{
	GtkWidget *page;
	const char *var_name;
	uint32_t attributes;
	int ret;

	if (var_data[id] != NULL) {
		free (var_data[id]);
		var_size[id] = 0;
	}

	var_name = mokvar_to_string[id];
	var_data[id] = NULL;
	ret = efi_get_variable (*var_guid[id], var_name, &var_data[id],
				&var_size[id], &attributes);
	if (ret < 0)
		var_data[id] = NULL;

	gtk_widget_hide (mokpage[id]);
	gtk_container_foreach (GTK_CONTAINER(mokpage[id]), destroy_children,
			       NULL);
	page = create_mok_page (id);
	gtk_box_pack_start (GTK_BOX(mokpage[id]), page, TRUE, TRUE, 0);
	update_tab (id);
}

static char *
get_cert_name_from_dialog (GtkWidget *window)
{
	GtkWidget *dialog;
	GtkFileChooserAction action = GTK_FILE_CHOOSER_ACTION_OPEN;
	char *filename = NULL;
	gint result;

	dialog = gtk_file_chooser_dialog_new (_("Choose a certificate"),
					      GTK_WINDOW(window),
					      action,
					      _("_Cancel"),
					      GTK_RESPONSE_CANCEL,
					      _("_Open"),
					      GTK_RESPONSE_ACCEPT,
					      NULL);
	result = gtk_dialog_run (GTK_DIALOG(dialog));
	if (result != GTK_RESPONSE_ACCEPT)
		goto out;

	filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER(dialog));
out:
	gtk_widget_destroy (dialog);

	return filename;
}

static int
read_file_to_buffer (const char *filename, uint8_t **buffer,
		     uint32_t *buf_size)
{
	struct stat f_stat;
	ssize_t read_size;
	int fd = 0, ret = -1;

	if (stat (filename, &f_stat) != 0)
			goto out;

	*buffer = (uint8_t *)malloc (f_stat.st_size);
	if (*buffer == NULL)
		return -1;

	fd = open (filename, O_RDONLY);
	if (fd == -1)
		return -1;

	read_size = read (fd, *buffer, f_stat.st_size);
	if (read_size < 0 || read_size != f_stat.st_size)
		goto out;

	*buf_size = (uint32_t)read_size;
	ret = 0;
out:
	if (fd > 0)
		close (fd);

	return ret;
}

static void
import_key (GtkWidget *window, MokRequest req)
{
	char *certname = NULL;
	uint8_t *cert = NULL;
	uint32_t cert_size;
	uint8_t *var_data = NULL, *new_var_data = NULL;
	uint8_t *ptr;
	size_t var_size, new_var_size;
	uint32_t attributes;
	char *password = NULL;
	gboolean root_pw;
	int ret;
	const char *var_name[] = {
		[ENROLL_MOK] = "MokNew",
		[ENROLL_BLACKLIST] = "MokXNew",
	};
	const char *authvar_name[] = {
		[ENROLL_MOK] = "MokAuth",
		[ENROLL_BLACKLIST] = "MokXAuth",
	};

	certname = get_cert_name_from_dialog (window);
	if (certname == NULL)
		return;

	if (read_file_to_buffer (certname, &cert, &cert_size) < 0) {
		show_err_dialog (GTK_WINDOW(window),
				 _("Failed to read file"));
		goto out;
	}

	if (!is_valid_cert(cert, cert_size)) {
		show_err_dialog (GTK_WINDOW(window),
				 _("Not a valid DER certificate"));
		goto out;
	}

	if (!is_valid_request (&efi_guid_x509_cert, cert, cert_size, req)) {
		show_err_dialog (GTK_WINDOW(window),
				 _("The key is already enrolled."));
		goto out;
	} else if (delete_from_pending_request (&efi_guid_x509_cert,
						cert, cert_size, req)) {
		const char *msg[] = {
			[ENROLL_MOK] = _("Removed the key from MokDel"),
			[ENROLL_BLACKLIST] = _("Removed the key from MokXDel"),
		};
		show_info_dialog (GTK_WINDOW(window), msg[req]);
	}

	/* Ask for the password */
	if (show_password_dialog (GTK_WINDOW(window), &password,
				  &root_pw) < 0)
		goto out;

	/* Read the variable and append the key */
	ret = efi_get_variable (efi_guid_shim, var_name[req], &var_data,
				&var_size, &attributes);
	if (ret < 0 && errno == ENOENT) {
		var_size = 0;
	} else if (ret < 0) {
		const char *msg[] = {
			[ENROLL_MOK] = _("Failed to get MokNew"),
			[ENROLL_BLACKLIST] = _("Failed to get MokXNew"),
		};
		show_err_dialog (GTK_WINDOW(window), msg[req]);
		goto out;
	}

	new_var_size = var_size + sizeof(EFI_SIGNATURE_LIST) +
		       sizeof (efi_guid_t) + cert_size;
	new_var_data = malloc (new_var_size);
	if (new_var_data == NULL) {
		show_err_dialog (GTK_WINDOW(window),
				 _("Failed to allocate memory"));
		goto out;
	}
	if (var_size > 0)
		memcpy (new_var_data, var_data, var_size);
	ptr = new_var_data + var_size;
	allocate_x509_sig (ptr, cert, cert_size);

	ret = efi_set_variable (efi_guid_shim, var_name[req], new_var_data,
				new_var_size, EFI_NV_RT, S_IRUSR | S_IWUSR);
	if (ret < 0) {
		show_err_dialog (GTK_WINDOW(window),
				 _("Failed to write the EFI variable"));
		goto out;
	}

	/* Generate the password hash */
	if (create_authvar (authvar_name[req], password, root_pw) < 0) {
		test_and_delete_var (var_name[req]);
		show_err_dialog (GTK_WINDOW(window),
				 _("Failed to generate password hash"));
		goto out;
	}

	/* Refresh MokNew or MokXNew page */
	if (req == ENROLL_MOK)
		refresh_page (MOK_NEW);
	else
		refresh_page (MOKX_NEW);

	show_info_dialog (GTK_WINDOW(window),
			  _("Please reboot the system for the change to take effect."));
out:
	if (certname != NULL)
		g_free (certname);
	if (cert != NULL)
		free (cert);
	if (password != NULL)
		free (password);
	if (var_data != NULL)
		free (var_data);
	if (new_var_data != NULL)
		free (new_var_data);
}

static void
import_mok_cb (GtkMenuItem * item __attribute__((unused)),
	       GtkWidget *window)
{
	import_key (window, ENROLL_MOK);
}

static void
import_mokx_cb (GtkMenuItem * item __attribute__((unused)),
	       GtkWidget *window)
{
	import_key (window, ENROLL_BLACKLIST);
}

static void
about_cb (GtkMenuItem * item __attribute__((unused)),
	  GtkWidget *window)
{
	const char *authors[] = {"Gary Lin", NULL};

	gtk_show_about_dialog (GTK_WINDOW(window),
			       "version", VERSION,
			       "copyright", "GPL-3.0",
			       "authors", authors,
			       NULL);
}

static void
generate_menubar_menus (GtkWidget *menu_bar, GtkWidget *window)
{
	GtkWidget *filemenu, *helpmenu;
	GtkWidget *file, *quit, *mok, *mokx;
	GtkWidget *help_top, *help, *about;
	GtkAccelGroup *accel_group;

	accel_group = gtk_accel_group_new ();
	gtk_window_add_accel_group (GTK_WINDOW (window), accel_group);

	/* File Menu */
	filemenu = gtk_menu_new ();

	mok = gtk_menu_item_new_with_label (_("Enroll a new key"));
	g_signal_connect (G_OBJECT(mok), "activate",
			  G_CALLBACK(import_mok_cb), window);
	gtk_widget_add_accelerator (mok, "activate", accel_group,
				    GDK_KEY_e, GDK_CONTROL_MASK,
				    GTK_ACCEL_VISIBLE);
	gtk_menu_shell_append (GTK_MENU_SHELL(filemenu), mok);

	mokx = gtk_menu_item_new_with_label (_("Blacklist a key"));
	g_signal_connect (G_OBJECT(mokx), "activate",
			  G_CALLBACK(import_mokx_cb), window);
	gtk_widget_add_accelerator (mokx, "activate", accel_group,
				    GDK_KEY_b, GDK_CONTROL_MASK,
				    GTK_ACCEL_VISIBLE);
	gtk_menu_shell_append (GTK_MENU_SHELL(filemenu), mokx);

	gtk_menu_shell_append (GTK_MENU_SHELL(filemenu),
			       gtk_separator_menu_item_new ());

	quit = gtk_menu_item_new_with_label (_("Quit"));
	g_signal_connect (G_OBJECT(quit), "activate",
			  G_CALLBACK(gtk_main_quit), NULL);
	gtk_widget_add_accelerator (quit, "activate", accel_group,
				    GDK_KEY_q, GDK_CONTROL_MASK,
				    GTK_ACCEL_VISIBLE);
	gtk_menu_shell_append (GTK_MENU_SHELL(filemenu), quit);

	file = gtk_menu_item_new_with_label (_("File"));
	gtk_menu_item_set_submenu (GTK_MENU_ITEM(file), filemenu);
	gtk_menu_shell_append (GTK_MENU_SHELL(menu_bar), file);

	/* Help Menu */
	helpmenu = gtk_menu_new ();

	help = gtk_menu_item_new_with_label (_("Help"));
	/* TODO Implement the help window */
	gtk_widget_add_accelerator (help, "activate", accel_group,
				    GDK_KEY_F1, 0, GTK_ACCEL_VISIBLE);
	gtk_menu_shell_append (GTK_MENU_SHELL(helpmenu), help);

	about = gtk_menu_item_new_with_label (_("About"));
	g_signal_connect (G_OBJECT(about), "activate",
			  G_CALLBACK(about_cb), window);
	gtk_menu_shell_append (GTK_MENU_SHELL(helpmenu), about);

	help_top = gtk_menu_item_new_with_label (_("Help"));
	gtk_menu_item_set_submenu (GTK_MENU_ITEM(help_top), helpmenu);
	gtk_menu_shell_append (GTK_MENU_SHELL(menu_bar), help_top);
}

static void
show_ui(void)
{
	GtkWidget *window, *vbox;
	GtkWidget *menu_bar, *pages;

	window = gtk_window_new (GTK_WINDOW_TOPLEVEL);
	gtk_window_set_default_size (GTK_WINDOW(window), 600, 400);
	/* TODO free var_data[] and list[] on exit */
	g_signal_connect (window, "destroy",
		          G_CALLBACK (gtk_main_quit), NULL);
	gtk_window_set_title (GTK_WINDOW(window), "mokutil");

	vbox = gtk_box_new (GTK_ORIENTATION_VERTICAL, 5);
	gtk_container_add (GTK_CONTAINER(window), vbox);

	menu_bar = gtk_menu_bar_new ();
	gtk_box_pack_start (GTK_BOX(vbox), menu_bar, FALSE, FALSE, 0);
	generate_menubar_menus (menu_bar, window);

	gtk_widget_show_all (window);

	pages = gtk_notebook_new ();
	gtk_box_pack_start (GTK_BOX(vbox), pages, FALSE, FALSE, 0);
	gtk_notebook_set_scrollable (GTK_NOTEBOOK(pages), TRUE);
	gtk_widget_show (pages);
	generate_pages (pages);
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
