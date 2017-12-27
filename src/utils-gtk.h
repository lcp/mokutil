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

#ifndef __UTILS_GTK_H__
#define __UTILS_GTK_H__

#include <ctype.h>

#include <glib/gi18n.h>
#include <gtk/gtk.h>

void show_info_dialog (GtkWindow *parent, const char *msg);
void show_err_dialog (GtkWindow *parent, const char *msg);
int show_password_dialog (GtkWindow *parent, char **password,
			  gboolean *root_pw);
char *get_cert_name_from_dialog (GtkWindow *parent);
void show_cert_details (GtkWindow *parent, const void *cert_data,
			const uint32_t cert_size);
int process_mok_request (GtkWindow *parent, const MokRequest req,
			 const efi_guid_t *type,
			 const void *key, const uint32_t key_size);
#endif /* __UTILS_GTK_H__ */
