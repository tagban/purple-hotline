/*
 * purple-hotline: chat rooms. See hl_room.h.
 * Copyright (c) 2026 John Leighow. MIT license.
 */
#include "hl_room.h"
#include "hl_wire.h"

#include <errno.h>
#ifndef _WIN32
#include <sys/socket.h>
#include <unistd.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "conversation.h"
#include "debug.h"
#include "eventloop.h"
#include "proxy.h"
#include "server.h"
#include "util.h"
#ifdef _WIN32
#include "win32dep.h"   /* libpurple's Winsock read/write/close/setsockopt (after glib) */
#endif

/* What a classic session claims to be: a 1.9 client, which every server knows. */
#define CLASSIC_VERSION 190
/* The classic icon people from Adium and Pidgin wear in rooms: 2537, Daffy Duck. */
#define ROOM_ICON 2537

enum {
	TX_SEND_PRIVATE = 108,
	TX_CHAT_SEND = 105,
	TX_CHAT_MSG = 106,
	TX_GET_USERS = 300,
	TX_USER_CHANGED = 301,
	TX_USER_LEFT = 302,
	F_CHAT_OPTIONS = 109,
	F_USER_FLAGS = 112,
	F_CHAT_ID = 114,
	F_USER_WITH_INFO = 300
};

enum { R_CONNECTING, R_HANDSHAKE, R_LOGIN, R_IN, R_LEFT };

struct _HlRoom {
	PurpleConnection *gc;
	int id;
	char *host;
	int port;
	char *address;   /* as the chat is named */
	char *nick;
	PurpleProxyConnectData *connect_data;
	int fd;
	guint read_h, write_h;
	GByteArray *in, *out;
	int state;
	guint32 next_id, login_id, users_id;
	gboolean utf8;
	GHashTable *users;   /* user ID -> the name shown in the room */
};

/* ---- text ---- */

static char *decode(HlRoom *r, const guint8 *d, gsize n)
{
	char *s;
	if (r->utf8 && g_utf8_validate((const char *)d, (gssize)n, NULL))
		return g_strndup((const char *)d, n);
	s = g_convert((const char *)d, (gssize)n, "UTF-8", "MACINTOSH", NULL, NULL, NULL);
	return s ? s : g_strndup((const char *)d, n);
}

static char *field_str(HlRoom *r, const HlTxn *t, guint16 id)
{
	const HlField *f = hl_txn_get(t, id);
	return f ? decode(r, f->data, f->len) : NULL;
}

static void b_text(HlRoom *r, HlBuilder *b, guint16 id, const char *s)
{
	char *e = NULL;
	gsize n = 0;
	if (!r->utf8)
		e = g_convert_with_fallback(s, -1, "MACINTOSH", "UTF-8", (gchar *)"?", NULL, &n, NULL);
	if (e) {
		hl_b_bytes(b, id, e, n);
		g_free(e);
	} else {
		hl_b_str(b, id, s);
	}
}

static PurpleConvChat *chat_of(HlRoom *r)
{
	PurpleConversation *c = purple_find_chat(r->gc, r->id);
	return c ? PURPLE_CONV_CHAT(c) : NULL;
}

static void say_system(HlRoom *r, const char *text)
{
	PurpleConversation *c = purple_find_chat(r->gc, r->id);
	char *e = g_markup_escape_text(text, -1);
	if (c)
		purple_conversation_write(c, NULL, e, PURPLE_MESSAGE_SYSTEM, time(NULL));
	g_free(e);
}

/* ---- the socket ---- */

static void drop(HlRoom *r)
{
	if (r->connect_data)
		purple_proxy_connect_cancel(r->connect_data);
	r->connect_data = NULL;
	if (r->read_h)
		purple_input_remove(r->read_h);
	if (r->write_h)
		purple_input_remove(r->write_h);
	r->read_h = r->write_h = 0;
	if (r->fd >= 0)
		close(r->fd);
	r->fd = -1;
}

/* The room stays open (to read back) with a note saying why it ended. */
static void ended(HlRoom *r, const char *why)
{
	PurpleConvChat *chat;
	if (r->state == R_LEFT)
		return;
	r->state = R_LEFT;
	drop(r);
	say_system(r, why);
	chat = chat_of(r);
	if (chat)
		purple_conv_chat_clear_users(chat);
	g_hash_table_remove_all(r->users);
}

static void write_cb(gpointer data, gint source, PurpleInputCondition cond);

static void flush(HlRoom *r)
{
	while (r->out->len > 0 && r->fd >= 0) {
		ssize_t n = write(r->fd, r->out->data, r->out->len);
		if (n < 0 && (errno == EAGAIN || errno == EINTR))
			break;
		if (n <= 0) {
			ended(r, "The connection to this room was lost.");
			return;
		}
		g_byte_array_remove_range(r->out, 0, (guint)n);
	}
	if (r->out->len > 0 && !r->write_h && r->fd >= 0)
		r->write_h = purple_input_add(r->fd, PURPLE_INPUT_WRITE, write_cb, r);
	else if (r->out->len == 0 && r->write_h) {
		purple_input_remove(r->write_h);
		r->write_h = 0;
	}
}

static void write_cb(gpointer data, gint source, PurpleInputCondition cond)
{
	flush((HlRoom *)data);
}

static guint32 send_txn(HlRoom *r, guint16 type, HlBuilder *b)
{
	guint32 id = r->next_id++;
	GByteArray *t = hl_b_finish(b, type, id);
	g_byte_array_append(r->out, t->data, t->len);
	g_byte_array_free(t, TRUE);
	flush(r);
	return id;
}

/* ---- people ---- */

static void ask_for_users(HlRoom *r)
{
	HlBuilder b;
	hl_b_init(&b);
	r->users_id = send_txn(r, TX_GET_USERS, &b);
}

typedef struct {
	guint uid;
	const char *name;
	gboolean taken;
} NameCheck;

static void check_name(gpointer k, gpointer v, gpointer data)
{
	NameCheck *c = (NameCheck *)data;
	if (GPOINTER_TO_UINT(k) != c->uid && strcmp((const char *)v, c->name) == 0)
		c->taken = TRUE;
}

/* A name not already used by someone else here (Hotline names needn't be unique).
 * (g_hash_table_foreach, not an iterator: Adium 1.3's glib predates those.) */
static char *unique_name(HlRoom *r, guint16 uid, const char *name)
{
	NameCheck c;
	c.uid = uid;
	c.name = *name ? name : "?";
	c.taken = FALSE;
	g_hash_table_foreach(r->users, check_name, &c);
	return c.taken ? g_strdup_printf("%s (%u)", c.name, uid) : g_strdup(c.name);
}

static PurpleConvChatBuddyFlags flags_of(guint16 hl_flags)
{
	return (hl_flags & 2) ? PURPLE_CBFLAGS_OP : PURPLE_CBFLAGS_NONE;   /* bit 1: an admin */
}

static void user_here(HlRoom *r, guint16 uid, const char *raw_name, guint16 hl_flags, gboolean arriving)
{
	PurpleConvChat *chat = chat_of(r);
	const char *old = (const char *)g_hash_table_lookup(r->users, GUINT_TO_POINTER((guint)uid));
	char *trimmed = g_strstrip(g_strdup(raw_name));
	char *name = unique_name(r, uid, trimmed);
	g_free(trimmed);
	if (!chat) {
		g_free(name);
		return;
	}
	if (old && strcmp(old, name) != 0) {
		purple_conv_chat_rename_user(chat, old, name);
	} else if (!old) {
		purple_conv_chat_add_user(chat, name, NULL, flags_of(hl_flags), arriving);
	} else {
		purple_conv_chat_user_set_flags(chat, name, flags_of(hl_flags));
	}
	g_hash_table_replace(r->users, GUINT_TO_POINTER((guint)uid), name);
}

static void users_reply(HlRoom *r, HlTxn *t)
{
	PurpleConvChat *chat = chat_of(r);
	guint i;
	if (!chat)
		return;
	purple_conv_chat_clear_users(chat);
	g_hash_table_remove_all(r->users);
	for (i = 0; i < t->nfields; i++) {
		const HlField *f = &t->fields[i];
		guint16 uid, flags, len;
		char *name;
		if (f->id != F_USER_WITH_INFO || f->len < 8)
			continue;
		uid = (guint16)((f->data[0] << 8) | f->data[1]);
		flags = (guint16)((f->data[4] << 8) | f->data[5]);
		len = (guint16)((f->data[6] << 8) | f->data[7]);
		if (len > f->len - 8)
			len = f->len - 8;
		name = decode(r, f->data + 8, len);
		user_here(r, uid, name, flags, FALSE);
		g_free(name);
	}
}

/* ---- what's said ---- */

/* Classic chat lines: "      name:  text", or " *** name does something" for an action. */
static void chat_line(HlRoom *r, const char *raw)
{
	const char *line = raw;
	const char *colon;
	time_t now = time(NULL);
	while (*line == ' ' || *line == '\t')
		line++;
	if (!*line)
		return;
	if (strncmp(line, "***", 3) == 0) {
		/* "*** name waves": libpurple shows actions from "/me ..." */
		const char *rest = line + 3;
		const char *sp;
		char *who, *msg, *e;
		while (*rest == ' ')
			rest++;
		sp = strchr(rest, ' ');
		who = sp ? g_strndup(rest, (gsize)(sp - rest)) : g_strdup(rest);
		e = g_markup_escape_text(sp ? sp + 1 : "", -1);
		msg = g_strdup_printf("/me %s", e);
		serv_got_chat_in(r->gc, r->id, who, strcmp(who, r->nick) == 0 ? PURPLE_MESSAGE_SEND : PURPLE_MESSAGE_RECV,
		                 msg, now);
		g_free(who);
		g_free(e);
		g_free(msg);
		return;
	}
	colon = strstr(line, ":  ");
	if (colon && colon > line && g_utf8_strlen(line, colon - line) <= 64) {
		char *who = g_strstrip(g_strndup(line, (gsize)(colon - line)));
		char *e = g_markup_escape_text(colon + 3, -1);
		serv_got_chat_in(r->gc, r->id, who,
		                 strcmp(who, r->nick) == 0 ? PURPLE_MESSAGE_SEND : PURPLE_MESSAGE_RECV, e, now);
		g_free(who);
		g_free(e);
		return;
	}
	say_system(r, line);
}

static void dispatch(HlRoom *r, HlTxn *t)
{
	if (t->is_reply) {
		if (t->id == r->login_id) {
			guint32 caps = 0;
			char *name;
			if (t->error != 0) {
				char *why = field_str(r, t, HL_F_ERROR);
				char *msg = g_strdup_printf("Couldn't join: %s", why && *why ? why : "the server said no.");
				ended(r, msg);
				g_free(why);
				g_free(msg);
				return;
			}
			hl_txn_uint(t, HL_F_CAPABILITIES, &caps);
			r->utf8 = (caps & HL_CAP_TEXT_ENCODING) != 0;
			r->state = R_IN;
			name = field_str(r, t, HL_F_SERVER_NAME);
			if (name && *g_strstrip(name)) {
				PurpleConversation *c = purple_find_chat(r->gc, r->id);
				if (c)
					purple_conversation_set_title(c, name);
			}
			g_free(name);
			ask_for_users(r);
		} else if (t->id == r->users_id && t->error == 0) {
			users_reply(r, t);
		}
		return;
	}
	switch (t->type) {
	case TX_CHAT_MSG: {
		char *text;
		gchar **lines;
		int i;
		if (hl_txn_get(t, F_CHAT_ID))
			break;   /* a private chat, not this room */
		text = field_str(r, t, HL_F_DATA);
		if (!text)
			break;
		lines = g_strsplit_set(text, "\r\n", -1);
		for (i = 0; lines[i]; i++)
			chat_line(r, lines[i]);
		g_strfreev(lines);
		g_free(text);
		break;
	}
	case TX_USER_CHANGED: {
		guint32 uid = 0, flags = 0;
		char *name = field_str(r, t, HL_F_USER_NAME);
		if (hl_txn_uint(t, HL_F_USER_ID, &uid) && name) {
			hl_txn_uint(t, F_USER_FLAGS, &flags);
			user_here(r, (guint16)uid, name, (guint16)flags, TRUE);
		}
		g_free(name);
		break;
	}
	case TX_USER_LEFT: {
		guint32 uid = 0;
		PurpleConvChat *chat = chat_of(r);
		const char *name;
		if (hl_txn_uint(t, HL_F_USER_ID, &uid) &&
		    (name = (const char *)g_hash_table_lookup(r->users, GUINT_TO_POINTER((guint)uid)))) {
			if (chat)
				purple_conv_chat_remove_user(chat, name, NULL);
			g_hash_table_remove(r->users, GUINT_TO_POINTER((guint)uid));
		}
		break;
	}
	case HL_TX_SHOW_AGREEMENT: {
		/* Agreements are accepted without showing them, as HIM does. */
		HlBuilder b;
		hl_b_init(&b);
		b_text(r, &b, HL_F_USER_NAME, r->nick);
		hl_b_int(&b, HL_F_USER_ICON_ID, ROOM_ICON);
		hl_b_int(&b, HL_F_OPTIONS, 0);
		send_txn(r, HL_TX_AGREED, &b);
		ask_for_users(r);   /* some servers list people only after this */
		break;
	}
	case HL_TX_SERVER_MSG: {
		guint32 uid;
		char *text = field_str(r, t, HL_F_DATA);
		if (text && hl_txn_uint(t, HL_F_USER_ID, &uid)) {
			/* A Hotline private message: its own conversation, named "name@room", so
			 * replies go back the same way (hl_room_send_private). */
			const char *shown = (const char *)g_hash_table_lookup(r->users, GUINT_TO_POINTER((guint)uid));
			char *from = shown ? g_strdup(shown) : field_str(r, t, HL_F_USER_NAME);
			char *who = g_strdup_printf("%s@%s", from && *from ? from : "?", r->address);
			char *e = g_markup_escape_text(text, -1);
			char *br = purple_strdup_withhtml(e);
			serv_got_im(r->gc, who, br, PURPLE_MESSAGE_RECV, time(NULL));
			g_free(from);
			g_free(who);
			g_free(e);
			g_free(br);
		} else if (text) {
			say_system(r, text);
		}
		g_free(text);
		break;
	}
	case HL_TX_DISCONNECT_MSG: {
		char *text = field_str(r, t, HL_F_DATA);
		char *msg = g_strdup_printf("You left the room: %s", text && *text ? text : "the server disconnected you.");
		ended(r, msg);
		g_free(text);
		g_free(msg);
		break;
	}
	default:
		break;
	}
}

static void read_cb(gpointer data, gint source, PurpleInputCondition cond)
{
	HlRoom *r = (HlRoom *)data;
	guint8 buf[8192];
	ssize_t n = read(r->fd, buf, sizeof buf);
	if (n < 0 && (errno == EAGAIN || errno == EINTR))
		return;
	if (n <= 0) {
		ended(r, "You left the room: the server closed the connection.");
		return;
	}
	g_byte_array_append(r->in, buf, (guint)n);

	if (r->state == R_HANDSHAKE) {
		HlBuilder b;
		if (r->in->len < 8)
			return;
		if (memcmp(r->in->data, "TRTP", 4) != 0 || r->in->data[4] | r->in->data[5] | r->in->data[6] | r->in->data[7]) {
			ended(r, "Couldn't join: that isn't a Hotline server.");
			return;
		}
		g_byte_array_remove_range(r->in, 0, 8);
		/* A guest: empty login and password, our name, Daffy's icon. */
		hl_b_init(&b);
		hl_b_bytes(&b, HL_F_USER_LOGIN, NULL, 0);
		hl_b_bytes(&b, HL_F_USER_PASSWORD, NULL, 0);
		hl_b_str(&b, HL_F_USER_NAME, r->nick);
		hl_b_int(&b, HL_F_USER_ICON_ID, ROOM_ICON);
		hl_b_int(&b, HL_F_VERSION, CLASSIC_VERSION);
		hl_b_u16(&b, HL_F_CAPABILITIES, HL_CAP_TEXT_ENCODING);
		r->state = R_LOGIN;
		r->login_id = send_txn(r, HL_TX_LOGIN, &b);
	}

	while (r->state == R_LOGIN || r->state == R_IN) {
		guint32 total, part;
		HlTxn *t;
		if (r->in->len < HL_HEADER_LEN)
			return;
		hl_header_sizes(r->in->data, &total, &part);
		if (part > HL_MAX_TXN || total > HL_MAX_TXN) {
			ended(r, "You left the room: the server sent something broken.");
			return;
		}
		if (total != part) {
			/* A transaction in parts: rare in chat; wait for all of it, then join the parts. */
			GByteArray *payload = g_byte_array_new();
			gsize off = HL_HEADER_LEN;
			guint32 got = 0;
			gboolean whole = FALSE;
			for (;;) {
				if (r->in->len < off + part)
					break;
				g_byte_array_append(payload, r->in->data + off, part);
				off += part;
				got += part;
				if (got >= total) {
					whole = TRUE;
					break;
				}
				if (r->in->len < off + HL_HEADER_LEN)
					break;
				{
					guint32 t2;
					hl_header_sizes(r->in->data + off, &t2, &part);
				}
				off += HL_HEADER_LEN;
				if (part == 0 || got + part > HL_MAX_TXN)
					break;
			}
			if (!whole) {
				g_byte_array_free(payload, TRUE);
				return;
			}
			t = hl_txn_parse(r->in->data, payload->data, payload->len);
			g_byte_array_free(payload, TRUE);
			g_byte_array_remove_range(r->in, 0, (guint)off);
		} else {
			if (r->in->len < HL_HEADER_LEN + part)
				return;
			t = hl_txn_parse(r->in->data, r->in->data + HL_HEADER_LEN, part);
			g_byte_array_remove_range(r->in, 0, HL_HEADER_LEN + part);
		}
		if (!t) {
			ended(r, "You left the room: the server sent something broken.");
			return;
		}
		dispatch(r, t);
		hl_txn_free(t);
	}
}

static void connected(gpointer data, gint source, const gchar *error)
{
	HlRoom *r = (HlRoom *)data;
	int on = 1;
	r->connect_data = NULL;
	if (source < 0) {
		char *msg = g_strdup_printf("Couldn't join: %s", error ? error : "the server didn't answer.");
		ended(r, msg);
		g_free(msg);
		return;
	}
	r->fd = source;
	setsockopt(source, SOL_SOCKET, SO_KEEPALIVE, (const char *)&on, sizeof on);
	r->state = R_HANDSHAKE;
	r->read_h = purple_input_add(source, PURPLE_INPUT_READ, read_cb, r);
	g_byte_array_append(r->out, (const guint8 *)"TRTPHOTL\0\1\0\0", 12);
	flush(r);
}

/* ---- the API ---- */

gboolean hl_parse_address(const char *address, char **host, int *port)
{
	char *a, *colon;
	if (!address)
		return FALSE;
	a = g_strstrip(g_strdup(address));
	if (g_str_has_prefix(a, "hotline://")) {
		char *rest = g_strdup(a + 10);
		g_free(a);
		a = rest;
	}
	if (*a && a[strlen(a) - 1] == '/')
		a[strlen(a) - 1] = 0;
	colon = strrchr(a, ':');
	*port = 5500;
	if (colon && !strchr(colon + 1, ']')) {
		int p = atoi(colon + 1);
		if (p > 0 && p < 65536) {
			*port = p;
			*colon = 0;
		}
	}
	if (!*a) {
		g_free(a);
		return FALSE;
	}
	*host = a;
	return TRUE;
}

HlRoom *hl_room_join(PurpleConnection *gc, int id, const char *host, int port, const char *nick)
{
	HlRoom *r = g_new0(HlRoom, 1);
	r->gc = gc;
	r->id = id;
	r->host = g_strdup(host);
	r->port = port;
	r->address = port == 5500 ? g_strdup(host) : g_strdup_printf("%s:%d", host, port);
	r->nick = g_strdup(nick);
	r->fd = -1;
	r->in = g_byte_array_new();
	r->out = g_byte_array_new();
	r->next_id = 1;
	r->utf8 = FALSE;   /* until the server says it speaks UTF-8 */
	r->users = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);
	r->state = R_CONNECTING;
	r->connect_data = purple_proxy_connect(gc, purple_connection_get_account(gc), host, port, connected, r);
	if (!r->connect_data)
		ended(r, "Couldn't join: couldn't start connecting.");
	return r;
}

void hl_room_send(HlRoom *r, const char *text)
{
	HlBuilder b;
	if (r->state != R_IN)
		return;
	hl_b_init(&b);
	if (g_str_has_prefix(text, "/me ")) {
		b_text(r, &b, HL_F_DATA, text + 4);
		hl_b_int(&b, F_CHAT_OPTIONS, 1);   /* the "alternate" style: an action */
	} else {
		b_text(r, &b, HL_F_DATA, text);
	}
	send_txn(r, TX_CHAT_SEND, &b);
}

const char *hl_room_address(HlRoom *r)
{
	return r->address;
}

typedef struct {
	const char *name;
	guint uid;
	gboolean found;
} FindUser;

static void find_user(gpointer k, gpointer v, gpointer data)
{
	FindUser *f = (FindUser *)data;
	if (!f->found && g_ascii_strcasecmp((const char *)v, f->name) == 0) {
		f->uid = GPOINTER_TO_UINT(k);
		f->found = TRUE;
	}
}

const char *hl_room_send_private(HlRoom *r, const char *name, const char *text)
{
	FindUser f;
	HlBuilder b;
	if (r->state != R_IN)
		return "You're not in that room any more.";
	f.name = name;
	f.uid = 0;
	f.found = FALSE;
	g_hash_table_foreach(r->users, find_user, &f);
	if (!f.found)
		return "They've left the room.";
	hl_b_init(&b);
	hl_b_int(&b, HL_F_USER_ID, f.uid);
	hl_b_int(&b, HL_F_OPTIONS, 1);   /* a user message */
	b_text(r, &b, HL_F_DATA, text);
	send_txn(r, TX_SEND_PRIVATE, &b);
	return NULL;
}

void hl_room_leave(HlRoom *r)
{
	if (!r)
		return;
	if (r->fd >= 0 && r->out->len > 0)
		flush(r);
	r->state = R_LEFT;
	drop(r);
	g_byte_array_free(r->in, TRUE);
	g_byte_array_free(r->out, TRUE);
	g_hash_table_destroy(r->users);
	g_free(r->host);
	g_free(r->address);
	g_free(r->nick);
	g_free(r);
}
