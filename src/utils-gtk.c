/**
 * Copyright (C) 2017 Gary Lin <glin@suse.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 *
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 */
#include <glib/gi18n.h>
#include <gtk/gtk.h>

#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "utils.h"
#include "utils-gtk.h"

void
show_info_dialog (GtkWindow *parent, const char *msg)
{
	GtkWidget *dialog;

	dialog = gtk_message_dialog_new (parent,
					 GTK_DIALOG_DESTROY_WITH_PARENT,
					 GTK_MESSAGE_INFO,
					 GTK_BUTTONS_OK,
					 "%s", _("Information"));
	gtk_message_dialog_format_secondary_text (GTK_MESSAGE_DIALOG(dialog),
						  "%s", msg);

	gtk_dialog_run (GTK_DIALOG(dialog));
	gtk_widget_destroy (dialog);
}

void
show_err_dialog (GtkWindow *parent, const char *msg)
{
	GtkWidget *dialog;

	dialog = gtk_message_dialog_new (parent,
					 GTK_DIALOG_DESTROY_WITH_PARENT,
					 GTK_MESSAGE_ERROR,
					 GTK_BUTTONS_OK,
					 "%s", _("Error"));
	gtk_message_dialog_format_secondary_text (GTK_MESSAGE_DIALOG(dialog),
						  "%s", msg);

	gtk_dialog_run (GTK_DIALOG(dialog));
	gtk_widget_destroy (dialog);
}

/* === show_password_dialog === */
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

int
show_password_dialog (GtkWindow *parent, char **password, gboolean *root_pw)
{
	GtkWidget *dialog, *content, *grid;
	GtkWidget *label, *root_check;
	GtkWidget *pwd_entry[2];
	GtkDialogFlags flags;
	gint result;
	const gchar *pwd1, *pwd2;

	*root_pw = FALSE;

	flags = GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT;
	dialog = gtk_dialog_new_with_buttons (_("Password"),
					      parent, flags,
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

	grid = gtk_grid_new ();
	gtk_grid_set_column_spacing (GTK_GRID(grid), 5);
	gtk_grid_set_row_spacing (GTK_GRID(grid), 5);

	label = gtk_label_new (_("Password:"));
	gtk_label_set_xalign (GTK_LABEL(label), 1.0);
	gtk_grid_attach (GTK_GRID(grid), label, 0, 0, 1, 1);

	pwd_entry[0] = gtk_entry_new ();
	gtk_entry_set_activates_default (GTK_ENTRY(pwd_entry[0]), TRUE);
	gtk_entry_set_visibility (GTK_ENTRY(pwd_entry[0]), FALSE);
	gtk_entry_set_input_purpose (GTK_ENTRY(pwd_entry[0]),
				     GTK_INPUT_PURPOSE_PASSWORD);
	gtk_grid_attach (GTK_GRID(grid), pwd_entry[0], 1, 0, 1, 1);

	label = gtk_label_new (_("Again:"));
	gtk_label_set_xalign (GTK_LABEL(label), 1.0);
	gtk_grid_attach (GTK_GRID(grid), label, 0, 1, 1, 1);

	pwd_entry[1] = gtk_entry_new ();
	gtk_entry_set_activates_default (GTK_ENTRY(pwd_entry[1]), TRUE);
	gtk_entry_set_visibility (GTK_ENTRY(pwd_entry[1]), FALSE);
	gtk_entry_set_input_purpose (GTK_ENTRY(pwd_entry[1]),
				     GTK_INPUT_PURPOSE_PASSWORD);
	gtk_grid_attach (GTK_GRID(grid), pwd_entry[1], 1, 1, 1, 1);

	gtk_container_add (GTK_CONTAINER(content), grid);

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

char *
get_cert_name_from_dialog (GtkWindow *parent)
{
	GtkWidget *dialog;
	GtkFileChooserAction action = GTK_FILE_CHOOSER_ACTION_OPEN;
	char *filename = NULL;
	gint result;

	dialog = gtk_file_chooser_dialog_new (_("Choose a certificate"),
					      parent,
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

/* === show_cert_details === */
static void
add_cert_row (GtkWidget *grid, int row, const char *type_str, const char *str)
{
	GtkWidget *type, *key;

	if (type_str) {
		type = gtk_label_new (NULL);
		gtk_label_set_xalign (GTK_LABEL(type), 1.0);
		gtk_label_set_yalign (GTK_LABEL(type), 0.0);
		gtk_label_set_markup (GTK_LABEL(type), type_str);
		gtk_grid_attach (GTK_GRID(grid), type, 0, row, 1, 1);
	}

	if (str) {
		key = gtk_label_new (str);
		gtk_label_set_xalign (GTK_LABEL(key), 0.0);
		gtk_label_set_yalign (GTK_LABEL(key), 0.0);
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

	add_cert_row (grid, (*row)++, "SHA1", output);

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

	add_cert_row (grid, (*row)++, "SHA256", output);
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
	{NID_commonName, N_("Name")},
	{NID_organizationName, N_("Organization")},
	{NID_organizationalUnitName, N_("Organizational Unit")},
	{NID_countryName, N_("Country")},
	{NID_stateOrProvinceName, N_("State/Provice")},
	{NID_localityName, N_("Locality")},
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
			add_cert_row (grid, (*row)++, _(nidname[i].name), str);
	}
}

void
show_cert_details (GtkWindow *parent, const void *cert_data,
		   const uint32_t cert_size)
{
	GtkWidget *dialog, *content, *frame, *grid;
	GtkDialogFlags flags;
	X509 *X509cert;
	X509_NAME *x509name;
	BIO *cert_bio;
	char *type_str, *str;
	int row_count;

	/* Convert DER to X509 structure */
	cert_bio = BIO_new (BIO_s_mem());
	if (cert_bio == NULL) {
		show_err_dialog (parent, _("Failed to allocate BIO"));
		return;
	}
	BIO_write (cert_bio, cert_data, cert_size);
	X509cert = d2i_X509_bio (cert_bio, NULL);
	if (X509cert == NULL) {
		show_err_dialog (parent, _("Invalid certificate"));
		return;
	}

	/* Create the dialog window */
	flags = GTK_DIALOG_DESTROY_WITH_PARENT | GTK_DIALOG_MODAL;
	dialog = gtk_dialog_new_with_buttons (_("Certificate Details"),
					      parent, flags,
					      _("Close"), GTK_RESPONSE_NONE,
					      NULL);
	content = gtk_dialog_get_content_area (GTK_DIALOG(dialog));
	gtk_container_set_border_width (GTK_CONTAINER(content), 10);
	gtk_box_set_spacing (GTK_BOX(content), 10);

	frame = gtk_frame_new (NULL);
	gtk_container_add (GTK_CONTAINER(content), frame);

	grid = gtk_grid_new ();
	gtk_container_add (GTK_CONTAINER(frame), grid);
	gtk_container_set_border_width (GTK_CONTAINER(grid), 10);
	gtk_grid_set_column_spacing (GTK_GRID(grid), 10);
	gtk_grid_set_row_spacing (GTK_GRID(grid), 4);
	row_count = 0;

	/* Versioni Number */
	type_str = g_strdup_printf ("<b>%s</b>", _("Version:"));
	str = g_strdup_printf ("%0ld", X509_get_version (X509cert) + 1);
	add_cert_row (grid, row_count++, type_str, str);
	g_free (type_str);
	g_free (str);

	/* Serial Number */
	type_str = g_strdup_printf ("<b>%s</b>", _("Serial:"));
	str = get_x509_serial_str (X509cert);
	add_cert_row (grid, row_count++, type_str, str);
	g_free (type_str);
	if (str)
		free (str);

	/* ==== */
	add_cert_row (grid, row_count++, " ", NULL);

	/* Signature Type */
	type_str = g_strdup_printf ("<b>%s</b>", _("Signature Type:"));
	str = (char *)get_x509_sig_alg_str (X509cert);
	add_cert_row (grid, row_count++, type_str, str);
	g_free (type_str);

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

	add_fingerprint_entries (grid, &row_count, cert_data, cert_size);

	str = get_x509_ext_str (X509cert, NID_key_usage);
	if (str != NULL) {
		/* ==== */
		add_cert_row (grid, row_count++, " ", NULL);

		/* Key Usage */
		type_str = g_strdup_printf ("<b>%s</b>", _("Key Usage:"));
		add_cert_row (grid, row_count++, type_str, str);

		g_free (type_str);
		free (str);
	}
	gtk_widget_show_all (content);

	gtk_dialog_run (GTK_DIALOG(dialog));

	gtk_widget_destroy (dialog);
}

/* === process_mok_request === */
int
process_mok_request (GtkWindow *parent, const MokRequest req,
		     const efi_guid_t *type, const void *key,
		     const uint32_t key_size)
{
	uint8_t *var_data = NULL, *new_var_data = NULL;
	uint8_t *ptr;
	size_t var_size, new_var_size;
	uint32_t attributes;
	char *password = NULL;
	gboolean root_pw;
	int ret = -1;
	const char *var_name[] = {
		[ENROLL_MOK] = "MokNew",
		[DELETE_MOK] = "MokDel",
		[ENROLL_BLACKLIST] = "MokXNew",
		[DELETE_BLACKLIST] = "MokXDel",
	};
	const char *authvar_name[] = {
		[ENROLL_MOK] = "MokAuth",
		[DELETE_MOK] = "MokDelAuth",
		[ENROLL_BLACKLIST] = "MokXAuth",
		[DELETE_BLACKLIST] = "MokXDelAuth",
	};

	if (key == NULL || key_size == 0)
		goto out;

	if (!is_valid_request (type, key, key_size, req)) {
		const char *msg[] = {
			[ENROLL_MOK] = _("Already enrolled"),
			[DELETE_MOK] = _("Already in the delete list"),
			[ENROLL_BLACKLIST] = _("Already in the blacklist"),
			[DELETE_BLACKLIST] = _("Already in the delete list"),
		};
		show_err_dialog (parent, msg[req]);
		goto out;
	} else if (delete_from_pending_request (type, key, key_size, req)) {
		const char *msg[] = {
			[ENROLL_MOK] = _("Removed the key from MokDel"),
			[DELETE_MOK] = _("Removed the key from MokNew"),
			[ENROLL_BLACKLIST] = _("Removed the key from MokXDel"),
			[DELETE_BLACKLIST] = _("Removed the key from MokXNew"),
		};
		show_info_dialog (parent, msg[req]);
		goto out;
	}

	/* Ask for the password */
	if (show_password_dialog (parent, &password, &root_pw) < 0)
		goto out;

	/* Read the variable and append the key */
	ret = efi_get_variable (efi_guid_shim, var_name[req], &var_data,
				&var_size, &attributes);
	if (ret < 0 && errno == ENOENT) {
		var_size = 0;
	} else if (ret < 0) {
		const char *msg[] = {
			[ENROLL_MOK] = _("Failed to get MokNew"),
			[DELETE_MOK] = _("Failed to get MokDel"),
			[ENROLL_BLACKLIST] = _("Failed to get MokXNew"),
			[DELETE_BLACKLIST] = _("Failed to get MokXDel"),
		};
		show_err_dialog (parent, msg[req]);
		goto out;
	}

	new_var_size = var_size + sizeof(EFI_SIGNATURE_LIST) +
		       sizeof (efi_guid_t) + key_size;
	new_var_data = malloc (new_var_size);
	if (new_var_data == NULL) {
		show_err_dialog (parent,
				 _("Failed to allocate memory"));
		goto out;
	}
	if (var_size > 0)
		memcpy (new_var_data, var_data, var_size);
	ptr = new_var_data + var_size;
	set_sig_header (ptr, type, key, key_size);

	ret = efi_set_variable (efi_guid_shim, var_name[req], new_var_data,
				new_var_size, EFI_NV_RT, S_IRUSR | S_IWUSR);
	if (ret < 0) {
		show_err_dialog (parent,
				 _("Failed to write the EFI variable"));
		goto out;
	}

	/* Generate the password hash */
	if (create_authvar (authvar_name[req], password, root_pw) < 0) {
		test_and_delete_var (var_name[req]);
		show_err_dialog (parent,
				 _("Failed to generate password hash"));
		goto out;
	}

	show_info_dialog (parent,
			  _("Please reboot the system for the change to "
			    "take effect."));
	ret = 0;
out:
	if (password != NULL)
		free (password);
	if (var_data != NULL)
		free (var_data);
	if (new_var_data != NULL)
		free (new_var_data);

	return ret;
}
