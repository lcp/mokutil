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
#include <openssl/x509v3.h>

#include "utils.h"
#include "utils-gtk.h"

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

GtkWidget *main_win;

/* For the key page tree view */
enum {
	TYPE_COLUMN,
	TYPE_ALIGN_COLUMN,
	KEY_COLUMN,
	N_COLUMNS
};

static void refresh_page (MOKVar id);

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
	gtk_tree_store_set (store, &iter, TYPE_COLUMN, "<b>X509</b>", -1);

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
	common_name = get_x509_name_str (X509_get_subject_name (X509cert),
					 NID_commonName);
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
	char *name, *type_str;

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

	type_str = g_strdup_printf ("<b>%s</b>", name);
	free (name);

	gtk_tree_store_append (store, &iter, NULL);
	gtk_tree_store_set (store, &iter, TYPE_COLUMN, type_str, -1);
	g_free (type_str);

	append_hash_entries (node, store, &iter);
}

static MOKVar cur_var_id;
static int cur_key_index;

static void
delete_key_cb (GtkMenuItem *menuitem __attribute__((unused)),
	       gpointer *data __attribute__((unused)))
{
	MokListNode *node;
	EFI_SIGNATURE_LIST *header;
	int ret;
	MokRequest req[] = {
		[MOK] = DELETE_MOK,
		[MOKX] = DELETE_BLACKLIST,
		[MOK_NEW] = DELETE_MOK,
		[MOK_DEL] = ENROLL_MOK,
		[MOKX_NEW] = DELETE_BLACKLIST,
		[MOKX_DEL] = ENROLL_BLACKLIST,
	};

	if (cur_var_id == DB || cur_var_id == DBX) {
		show_err_dialog (GTK_WINDOW(main_win),
				 _("Unsupported Operation"));
		return;
	}

	node = &list[cur_var_id][cur_key_index];
	header = node->header;

	/* TODO support hash deletion */
	if (efi_guid_cmp(&header->SignatureType, &efi_guid_x509_cert) != 0) {
		show_err_dialog (GTK_WINDOW(main_win),
				 _("Unsupported Operation"));
		return;
	}

	if (cur_var_id == MOK || cur_var_id == MOKX) {
		/* create MokDel or MokXDel */
		ret = process_mok_request (GTK_WINDOW(main_win),
					   req[cur_var_id],
					   node->mok, node->mok_size);
		if (ret < 0)
			return;

		if (cur_var_id == MOK)
			refresh_page (MOK_DEL);
		else
			refresh_page (MOKX_DEL);
		refresh_page (cur_var_id);
	} else if (cur_var_id == MOK_NEW || cur_var_id == MOKX_NEW ||
		   cur_var_id == MOK_DEL || cur_var_id == MOKX_DEL) {
		/* delete_from_pending_request() deletes the key in the
		 * opposite list. */
		delete_from_pending_request (&(header->SignatureType),
					     node->mok, node->mok_size,
					     req[cur_var_id]);
		refresh_page (cur_var_id);
	}
}

static void
detail_cb (GtkMenuItem *menuitem __attribute__((unused)),
	   gpointer *data __attribute__((unused)))
{
	MokListNode *node;

	node = &list[cur_var_id][cur_key_index];
	show_cert_details (GTK_WINDOW(main_win), node->mok, node->mok_size);
}

static gboolean
treeview_clicked (GtkTreeView *treeview, GdkEvent *event, MOKVar *id)
{
	GdkEventButton *button;
	GtkTreePath *path;
	GtkMenu *menu;
	GtkWidget *delete, *detail;
	char *path_str;
	MokListNode *node;
	efi_guid_t *type;

	button = (GdkEventButton *)event;

	/* Catch the double-click or the right button */
	if (!(button->type == GDK_BUTTON_PRESS &&
	      button->button == GDK_BUTTON_SECONDARY) &&
	    !(button->type == GDK_2BUTTON_PRESS &&
	      button->button == GDK_BUTTON_PRIMARY))
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

	node = &list[cur_var_id][cur_key_index];
	type = &node->header->SignatureType;
	if (efi_guid_cmp(type, &efi_guid_x509_cert) != 0)
		return FALSE;

	/* Show the details popup for the double-click */
	if ((button->type == GDK_2BUTTON_PRESS &&
	     button->button == GDK_BUTTON_PRIMARY)) {
		detail_cb (NULL, NULL);
		return FALSE;
	}

	/* Show the popup menu */
	menu = (GtkMenu *)gtk_menu_new ();

	if (*id != DB && *id != DBX) {
		delete = gtk_menu_item_new_with_label (_("Delete this key"));
		gtk_menu_attach (menu, delete, 0, 1, 0 ,1);
		g_signal_connect (G_OBJECT(delete), "activate",
				  G_CALLBACK(delete_key_cb), NULL);
	}

	detail = gtk_menu_item_new_with_label (_("Details"));
	gtk_menu_attach (menu, detail, 0, 1, 1 ,2);
	g_signal_connect (G_OBJECT(detail), "activate",
			  G_CALLBACK(detail_cb), NULL);

	gtk_widget_show_all (GTK_WIDGET(menu));
#if GTK_MAJOR_VERSION == 3 && GTK_MINOR_VERSION < 22
	gtk_menu_popup (menu, NULL, NULL, NULL, NULL, button->button,
			gtk_get_current_event_time());
#else
	gtk_menu_popup_at_pointer (menu, event);
#endif

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

static int
get_certificate (uint8_t **cert, uint32_t *cert_size)
{
	char *certname = NULL;
	int ret = -1;

	certname = get_cert_name_from_dialog (GTK_WINDOW(main_win));
	if (certname == NULL)
		return -1;

	if (read_file_to_buffer (certname, cert, cert_size) < 0) {
		show_err_dialog (GTK_WINDOW(main_win),
				 _("Failed to read file"));
		goto out;
	}

	if (!is_valid_cert(*cert, *cert_size)) {
		show_err_dialog (GTK_WINDOW(main_win),
				 _("Not a valid DER certificate"));
		goto out;
	}

	ret = 0;
out:
	g_free (certname);
	return ret;
}

static void
import_key (MokRequest req)
{
	uint8_t *cert = NULL;
	uint32_t cert_size;
	int ret;

	if (get_certificate (&cert, &cert_size) < 0)
		goto out;

	ret = process_mok_request (GTK_WINDOW(main_win), req, cert, cert_size);
	if (ret < 0)
		goto out;

	/* Refresh MokNew or MokXNew page */
	if (req == ENROLL_MOK)
		refresh_page (MOK_NEW);
	else
		refresh_page (MOKX_NEW);

out:
	if (cert != NULL)
		free (cert);
}

static void
import_mok_cb (GtkMenuItem * item __attribute__((unused)),
	       gpointer data __attribute__((unused)))
{
	import_key (ENROLL_MOK);
}

static void
import_mokx_cb (GtkMenuItem * item __attribute__((unused)),
	        gpointer data __attribute__((unused)))
{
	import_key (ENROLL_BLACKLIST);
}

static void
inspect_cb (GtkMenuItem * item __attribute__((unused)),
	    gpointer data __attribute__((unused)))
{
	uint8_t *cert = NULL;
	uint32_t cert_size;

	if (get_certificate (&cert, &cert_size) < 0)
		goto out;

	show_cert_details (GTK_WINDOW(main_win), cert, cert_size);
out:
	if (cert)
		free (cert);
}

static void
about_cb (GtkMenuItem * item __attribute__((unused)),
	  gpointer data __attribute__((unused)))
{
	const char *authors[] = {"Gary Lin", NULL};
	const char *comments = _("Utility to manipulate Machine Owner Key");
	const char *website = "https://github.com/lcp/mokutil";

	gtk_show_about_dialog (GTK_WINDOW(main_win),
			       "version", VERSION,
			       "copyright", "GPL-3.0",
			       "authors", authors,
			       "comments", comments,
			       "website", website,
			       NULL);
}

static void
generate_menubar_menus (GtkWidget *menu_bar)
{
	GtkWidget *file, *help, *menu, *item;
	GtkAccelGroup *accel_group;

	accel_group = gtk_accel_group_new ();
	gtk_window_add_accel_group (GTK_WINDOW(main_win), accel_group);

	/* File Menu */
	menu = gtk_menu_new ();

	item = gtk_menu_item_new_with_label (_("Enroll a new key"));
	g_signal_connect (G_OBJECT(item), "activate",
			  G_CALLBACK(import_mok_cb), NULL);
	gtk_widget_add_accelerator (item, "activate", accel_group,
				    GDK_KEY_e, GDK_CONTROL_MASK,
				    GTK_ACCEL_VISIBLE);
	gtk_menu_shell_append (GTK_MENU_SHELL(menu), item);

	item = gtk_menu_item_new_with_label (_("Blacklist a key"));
	g_signal_connect (G_OBJECT(item), "activate",
			  G_CALLBACK(import_mokx_cb), NULL);
	gtk_widget_add_accelerator (item, "activate", accel_group,
				    GDK_KEY_b, GDK_CONTROL_MASK,
				    GTK_ACCEL_VISIBLE);
	gtk_menu_shell_append (GTK_MENU_SHELL(menu), item);

	item = gtk_menu_item_new_with_label (_("Inspect a key"));
	g_signal_connect (G_OBJECT(item), "activate",
			  G_CALLBACK(inspect_cb), NULL);
	gtk_widget_add_accelerator (item, "activate", accel_group,
				    GDK_KEY_i, GDK_CONTROL_MASK,
				    GTK_ACCEL_VISIBLE);
	gtk_menu_shell_append (GTK_MENU_SHELL(menu), item);

	gtk_menu_shell_append (GTK_MENU_SHELL(menu),
			       gtk_separator_menu_item_new ());

	item = gtk_menu_item_new_with_label (_("Quit"));
	g_signal_connect (G_OBJECT(item), "activate",
			  G_CALLBACK(gtk_main_quit), NULL);
	gtk_widget_add_accelerator (item, "activate", accel_group,
				    GDK_KEY_q, GDK_CONTROL_MASK,
				    GTK_ACCEL_VISIBLE);
	gtk_menu_shell_append (GTK_MENU_SHELL(menu), item);

	file = gtk_menu_item_new_with_label (_("File"));
	gtk_menu_item_set_submenu (GTK_MENU_ITEM(file), menu);
	gtk_menu_shell_append (GTK_MENU_SHELL(menu_bar), file);

	/* Help Menu */
	menu = gtk_menu_new ();

	item = gtk_menu_item_new_with_label (_("About"));
	g_signal_connect (G_OBJECT(item), "activate",
			  G_CALLBACK(about_cb), NULL);
	gtk_menu_shell_append (GTK_MENU_SHELL(menu), item);

	help = gtk_menu_item_new_with_label (_("Help"));
	gtk_menu_item_set_submenu (GTK_MENU_ITEM(help), menu);
	gtk_menu_shell_append (GTK_MENU_SHELL(menu_bar), help);
}

static void
show_ui(void)
{
	GtkWidget *vbox, *menu_bar, *pages;

	main_win = gtk_window_new (GTK_WINDOW_TOPLEVEL);
	gtk_window_set_default_size (GTK_WINDOW(main_win), 600, 400);
	g_signal_connect (main_win, "destroy",
		          G_CALLBACK (gtk_main_quit), NULL);
	gtk_window_set_title (GTK_WINDOW(main_win), "mokutil-gtk");

	vbox = gtk_box_new (GTK_ORIENTATION_VERTICAL, 5);
	gtk_container_add (GTK_CONTAINER(main_win), vbox);

	menu_bar = gtk_menu_bar_new ();
	gtk_box_pack_start (GTK_BOX(vbox), menu_bar, FALSE, FALSE, 0);
	generate_menubar_menus (menu_bar);

	gtk_widget_show_all (main_win);

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
	bindtextdomain (PACKAGE, LOCALEDIR);
	bind_textdomain_codeset (PACKAGE, "UTF-8");
	textdomain (PACKAGE);
#endif
	gtk_init (&argc, &argv);
	show_ui ();
	gtk_main ();

	/* Clean up the arrays */
	for (int i = 0; i < NUM_OF_VARS; i++) {
		if (var_data[i]) {
			free (var_data[i]);
			var_data[i] = NULL;
		}

		if (list[i]) {
			free (list[i]);
			list[i] = NULL;
		}
	}

	return 0;
}
