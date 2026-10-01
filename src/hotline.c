/*
 * purple-hotline: Hotline Instant Messaging for libpurple (Pidgin, Adium, Finch).
 *
 * Speaks fogWraith's Hotline messaging extension (the 800 block) with HOPE secure
 * sign-in and its ChaCha20-Poly1305 transport, the way HIM does
 * (https://github.com/tagban/him). Buddy list, presence and away messages,
 * instant messages (offline delivery included), typing, buddy requests, blocking,
 * profiles and Buddy Icons.
 *
 * Kept to the libpurple 2.x API that Adium 1.3 already had, and to C that GCC 4.0
 * compiles, so it can be built for PowerPC Macs too.
 *
 * Copyright (c) 2026 John Leighow. MIT license (see LICENSE).
 */
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <glib.h>

#ifndef PURPLE_PLUGINS
#define PURPLE_PLUGINS
#endif

#include "account.h"
#include "accountopt.h"
#include "blist.h"
#include "buddyicon.h"
#include "connection.h"
#include "conversation.h"
#include "debug.h"
#include "eventloop.h"
#include "imgstore.h"
#include "notify.h"
#include "plugin.h"
#include "privacy.h"
#include "prpl.h"
#include "proxy.h"
#include "request.h"
#include "server.h"
#include "status.h"
#include "util.h"
#include "version.h"

#include "hl_crypto.h"
#include "hl_wire.h"

#define HL_PRPL_ID "prpl-hotline"
#define HL_VERSION "0.1.0"
#define HL_DEFAULT_SERVER "hotline.vespernet.net"
#define HL_DEFAULT_PORT 5500
#define HL_GROUP "Buddies"
/* Version (160): the HIM family's number, 1997 (AIM's year). */
#define HL_CLIENT_VERSION 1997
#define HL_APP_ID "HIMp"
#define HL_APP_STRING "HIM for libpurple " HL_VERSION
#define HL_OUR_CAPS (HL_CAP_MESSAGING | HL_CAP_MESSENGER_SESSION | HL_CAP_TEXT_ENCODING)

#define DBG(...) purple_debug_info("hotline", __VA_ARGS__)

/* Presence values (guide §11). */
enum { P_OFFLINE = 0, P_ONLINE = 1, P_AWAY = 2, P_INVISIBLE = 3, P_BUSY = 4 };
/* Roster states (guide §9). */
enum { R_REMOVED = 0, R_PENDING_OUT = 1, R_PENDING_IN = 2, R_ACCEPTED = 3, R_BLOCKED = 4 };

enum { MAC_INVERSE, MAC_SHA1, MAC_SHA256 };

enum { ST_HANDSHAKE, ST_IDENT, ST_LOGIN, ST_ONLINE };

typedef struct _HlConn HlConn;
typedef void (*HlReplyCb)(HlConn *hc, HlTxn *reply, gpointer data);

typedef struct {
	HlReplyCb cb;
	gpointer data;
	GDestroyNotify free_data;
} HlPending;

struct _HlConn {
	PurpleConnection *gc;
	PurpleAccount *account;
	PurpleProxyConnectData *connect_data;
	int fd;
	guint read_h, write_h;

	GByteArray *in;      /* bytes from the socket */
	GByteArray *plain;   /* transaction bytes (opened frames, or the socket's in the clear) */
	GByteArray *out;     /* waiting to be written */

	int stage;
	gboolean legacy;     /* the old sign-in: no HOPE (only if the account allows it) */

	/* HOPE */
	hl_u8 session_key[64];
	int mac;
	gboolean aead;       /* frames are sealed */
	gboolean first_sealed;
	hl_u8 key_out[32], key_in[32];
	guint64 ctr_out, ctr_in;

	guint32 next_id;
	GHashTable *pending;     /* task ID -> HlPending */
	GHashTable *asked;       /* logins we've shown a buddy request for this session */
	GHashTable *roster;      /* logins on the server's list (for tidying the local one) */

	gboolean dead;           /* an error was reported; libpurple signs off shortly */
	gboolean utf8;
	guint32 max_message;
	gboolean icons;
	guint32 max_icon_bytes;
};

/* ------------------------------------------------------------------ helpers */

/* Reports a connection error once; libpurple signs off a moment later. */
static void hl_error(HlConn *hc, PurpleConnectionError reason, const char *text)
{
	if (hc->dead)
		return;
	hc->dead = TRUE;
	purple_connection_error_reason(hc->gc, reason, text);
}

static int same(const char *a, const char *b)
{
	if (!a || !b)
		return a == b;
	return strcmp(a, b) == 0;
}

static gpointer copy_bytes(const guint8 *p, gsize n)
{
	gpointer d = g_malloc(n ? n : 1);
	memcpy(d, p, n);
	return d;
}

/* ------------------------------------------------------------------ text */

/* Server text into UTF-8: the session's encoding (UTF-8, or Mac Roman). */
static char *hl_decode(HlConn *hc, const guint8 *data, gsize len)
{
	char *s;
	if (hc->utf8 && g_utf8_validate((const char *)data, (gssize)len, NULL))
		return g_strndup((const char *)data, len);
	s = g_convert((const char *)data, (gssize)len, "UTF-8", "MACINTOSH", NULL, NULL, NULL);
	return s ? s : g_strndup((const char *)data, len);
}

static char *hl_field_str(HlConn *hc, const HlField *f)
{
	return f ? hl_decode(hc, f->data, f->len) : NULL;
}

/* Our text out: UTF-8 as it is, or Mac Roman for an older server. */
static char *hl_encode(HlConn *hc, const char *s, gsize *len)
{
	char *out;
	gsize n = 0;
	if (!s)
		s = "";
	if (!hc->utf8) {
		out = g_convert_with_fallback(s, -1, "MACINTOSH", "UTF-8", (gchar *)"?", NULL, &n, NULL);
		if (out) {
			*len = n;
			return out;
		}
	}
	*len = strlen(s);
	return g_strdup(s);
}

static void hl_b_text(HlConn *hc, HlBuilder *b, guint16 id, const char *s)
{
	gsize n;
	char *e = hl_encode(hc, s, &n);
	hl_b_bytes(b, id, e, n);
	g_free(e);
}

static gboolean blank(const char *s)
{
	if (!s)
		return TRUE;
	while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r')
		s++;
	return *s == 0;
}

static const char *reason_text(guint32 code)
{
	switch (code) {
	case 1: return "No such user.";
	case 2: return "That account can't use messaging.";
	case 3: return "You can't message this user.";
	case 4: return "You're already buddies.";
	case 5: return "Request already sent.";
	case 6: return "You must be buddies to do that.";
	case 7: return "Will deliver when they sign on.";
	case 8: return "User is offline.";
	case 9: return "Their inbox is full; try later.";
	case 10: return "Slow down a little.";
	case 11: return "No one found.";
	case 12: return "Your Buddy List is full.";
	case 13: return "That message (or picture) is too big.";
	case 14: return "The server couldn't use that picture.";
	default: return "The server refused.";
	}
}

/* The server's words for a refused request, or ours for its reason code. */
static char *reply_error(HlConn *hc, HlTxn *r)
{
	const HlField *f = hl_txn_get(r, HL_F_ERROR);
	guint32 reason = 0xFFFF;
	char *s = hl_field_str(hc, f);
	if (s && !blank(s))
		return s;
	g_free(s);
	hl_txn_uint(r, HL_F_REASON_CODE, &reason);
	return g_strdup(reason_text(reason));
}

/* ------------------------------------------------------------------ output */

static void hl_write_cb(gpointer data, gint source, PurpleInputCondition cond);

static void hl_flush(HlConn *hc)
{
	while (hc->out->len > 0) {
		ssize_t n = write(hc->fd, hc->out->data, hc->out->len);
		if (n < 0 && (errno == EAGAIN || errno == EINTR))
			break;
		if (n <= 0) {
			hl_error(hc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
			                               "The connection was lost.");
			return;
		}
		g_byte_array_remove_range(hc->out, 0, (guint)n);
	}
	if (hc->out->len > 0 && !hc->write_h)
		hc->write_h = purple_input_add(hc->fd, PURPLE_INPUT_WRITE, hl_write_cb, hc);
	else if (hc->out->len == 0 && hc->write_h) {
		purple_input_remove(hc->write_h);
		hc->write_h = 0;
	}
}

static void hl_write_cb(gpointer data, gint source, PurpleInputCondition cond)
{
	hl_flush((HlConn *)data);
}

static void nonce(hl_u8 n[12], hl_u8 dir, guint64 counter)
{
	int i;
	memset(n, 0, 12);
	n[0] = dir;
	for (i = 0; i < 8; i++)
		n[4 + i] = (hl_u8)(counter >> (56 - 8 * i));
}

/* Bytes onto the wire: sealed in a frame once HOPE's transport is on (guide §7.6). */
static void hl_write_raw(HlConn *hc, const guint8 *data, gsize len)
{
	if (hc->aead) {
		hl_u8 n[12], h[4];
		guint8 *sealed = g_malloc(len + 16);
		gsize total = len + 16;
		nonce(n, 0x01, hc->ctr_out++);
		hl_aead_seal(hc->key_out, n, data, len, sealed);
		h[0] = (hl_u8)(total >> 24); h[1] = (hl_u8)(total >> 16);
		h[2] = (hl_u8)(total >> 8); h[3] = (hl_u8)total;
		g_byte_array_append(hc->out, h, 4);
		g_byte_array_append(hc->out, sealed, (guint)total);
		g_free(sealed);
	} else {
		g_byte_array_append(hc->out, data, (guint)len);
	}
	hl_flush(hc);
}

static guint32 hl_next_id(HlConn *hc)
{
	if (hc->next_id == 0)
		hc->next_id = 1;
	return hc->next_id++;
}

/* Sends a request; `cb` (if any) gets the reply. Returns the task ID. */
static guint32 hl_send(HlConn *hc, guint16 type, HlBuilder *b, HlReplyCb cb, gpointer data,
                       GDestroyNotify free_data)
{
	guint32 id = hl_next_id(hc);
	GByteArray *t = hl_b_finish(b, type, id);
	if (cb) {
		HlPending *p = g_new0(HlPending, 1);
		p->cb = cb;
		p->data = data;
		p->free_data = free_data;
		g_hash_table_insert(hc->pending, GUINT_TO_POINTER(id), p);
	} else if (free_data && data) {
		free_data(data);
	}
	hl_write_raw(hc, t->data, t->len);
	g_byte_array_free(t, TRUE);
	return id;
}

static void pending_free(gpointer p)
{
	HlPending *x = (HlPending *)p;
	if (x->free_data && x->data)
		x->free_data(x->data);
	g_free(x);
}

/* ------------------------------------------------------------------ sign-on */

static void hl_connect(HlConn *hc);
static void hl_dispatch(HlConn *hc, HlTxn *t);
static void hl_after_login(HlConn *hc, HlTxn *r);

static void mac(int alg, const guint8 *key, gsize klen, const guint8 *msg, gsize mlen, guint8 *out, gsize *olen)
{
	gsize i;
	switch (alg) {
	case MAC_SHA256:
		hl_hmac_sha256(key, klen, msg, mlen, out);
		*olen = HL_SHA256_LEN;
		break;
	case MAC_SHA1:
		hl_hmac_sha1(key, klen, msg, mlen, out);
		*olen = HL_SHA1_LEN;
		break;
	default:   /* INVERSE: the legacy obfuscation of the key itself */
		for (i = 0; i < klen; i++)
			out[i] = (guint8)~key[i];
		*olen = klen;
	}
}

static int parse_mac(const char *name)
{
	if (!name)
		return MAC_INVERSE;
	if (g_ascii_strcasecmp(name, "HMAC-SHA256") == 0)
		return MAC_SHA256;
	if (g_ascii_strcasecmp(name, "HMAC-SHA1") == 0)
		return MAC_SHA1;
	return MAC_INVERSE;
}

static gboolean is_chacha(const HlField *f)
{
	char *n = hl_first_name(f);
	gboolean yes = n && (g_ascii_strcasecmp(n, "CHACHA20-POLY1305") == 0 ||
	                     g_ascii_strcasecmp(n, "CHACHA20POLY1305") == 0 ||
	                     g_ascii_strcasecmp(n, "CHACHA20") == 0);
	g_free(n);
	return yes;
}

static void add_login_fields(HlConn *hc, HlBuilder *b)
{
	const char *nick = purple_account_get_alias(hc->account);
	if (blank(nick))
		nick = purple_account_get_username(hc->account);
	hl_b_str(b, HL_F_USER_NAME, nick);   /* UTF-8 before negotiation */
	hl_b_int(b, HL_F_USER_ICON_ID, 0);
	hl_b_int(b, HL_F_VERSION, HL_CLIENT_VERSION);
	hl_b_u16(b, HL_F_CAPABILITIES, HL_OUR_CAPS);
}

static void login_reply(HlConn *hc, HlTxn *r, gpointer data)
{
	if (r->error != 0) {
		char *why = reply_error(hc, r);
		/* The server's own text when it gave one; "Incorrect login" otherwise. */
		hl_error(hc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
		                               blank(why) || strcmp(why, reason_text(0xFFFF)) == 0
		                                   ? "Incorrect login." : why);
		g_free(why);
		return;
	}
	hl_after_login(hc, r);
}

static void hope_reply(HlConn *hc, HlTxn *r, gpointer data)
{
	const HlField *key = hl_txn_get(r, HL_F_HOPE_SESSION_KEY);
	const HlField *macf = hl_txn_get(r, HL_F_HOPE_MAC_ALGORITHM);
	const HlField *login_f = hl_txn_get(r, HL_F_USER_LOGIN);
	const char *login = purple_account_get_username(hc->account);
	const char *password = purple_connection_get_password(hc->gc);
	char *alg_name;
	gboolean mac_login, aead;
	guint8 lm[256], pm[256];
	gsize lml, pml;
	HlBuilder b;
	static const char *const cipher[] = { "CHACHA20-POLY1305" };

	if (r->error != 0 || !key || key->len != 64) {
		/* No HOPE here. The old sign-in sends the password barely disguised. */
		if (purple_account_get_bool(hc->account, "allow_legacy", FALSE)) {
			DBG("no HOPE; signing in the old way\n");
			hc->legacy = TRUE;
			hl_connect(hc);
		} else {
			hl_error(hc, PURPLE_CONNECTION_ERROR_ENCRYPTION_ERROR,
				"This server doesn't offer secure sign-in (HOPE), so your password would be sent "
				"unprotected. To sign in anyway, turn on \"Allow sign-in without protecting the "
				"password\" in this account's options.");
		}
		return;
	}
	memcpy(hc->session_key, key->data, 64);
	alg_name = hl_first_name(macf);
	hc->mac = parse_mac(alg_name);
	g_free(alg_name);
	mac_login = login_f && login_f->len > 0;
	aead = hc->mac != MAC_INVERSE &&
	       is_chacha(hl_txn_get(r, HL_F_HOPE_SERVER_CIPHER)) &&
	       is_chacha(hl_txn_get(r, HL_F_HOPE_CLIENT_CIPHER));
	DBG("HOPE: %s, %s\n", hc->mac == MAC_SHA256 ? "HMAC-SHA256" : hc->mac == MAC_SHA1 ? "HMAC-SHA1" : "INVERSE",
	    aead ? "ChaCha20-Poly1305" : "no transport encryption");
	if (hc->mac == MAC_INVERSE && !purple_account_get_bool(hc->account, "allow_legacy", FALSE)) {
		hl_error(hc, PURPLE_CONNECTION_ERROR_ENCRYPTION_ERROR,
			"This server only offers the old, unprotected sign-in. To sign in anyway, turn on "
			"\"Allow sign-in without protecting the password\" in this account's options.");
		return;
	}

	/* Step 3: the authenticated login. */
	hl_b_init(&b);
	/* mac(key = login or password, message = session key); INVERSE inverts the key */
	if (mac_login && hc->mac != MAC_INVERSE)
		mac(hc->mac, (const guint8 *)login, strlen(login), hc->session_key, 64, lm, &lml);
	else
		mac(MAC_INVERSE, (const guint8 *)login, MIN(strlen(login), sizeof lm), NULL, 0, lm, &lml);
	hl_b_bytes(&b, HL_F_USER_LOGIN, lm, lml);
	if (hc->mac != MAC_INVERSE)
		mac(hc->mac, (const guint8 *)password, strlen(password), hc->session_key, 64, pm, &pml);
	else
		mac(MAC_INVERSE, (const guint8 *)password, MIN(strlen(password), sizeof pm), NULL, 0, pm, &pml);
	hl_b_bytes(&b, HL_F_USER_PASSWORD, pm, pml);
	add_login_fields(hc, &b);
	if (aead)
		hl_b_name_list(&b, HL_F_HOPE_SERVER_CIPHER, cipher, 1);
	hc->stage = ST_LOGIN;
	hl_send(hc, HL_TX_LOGIN, &b, login_reply, NULL, NULL);   /* in the clear */

	if (aead) {
		/* Keys named from the server's side: it writes with encode, reads with decode. */
		guint8 pmac[32], enc[32], dec[32];
		gsize n1, n2, n3;
		const guint8 *pw = (const guint8 *)password;
		gsize pwl = strlen(password);
		mac(hc->mac, pw, pwl, hc->session_key, 64, pmac, &n1);
		mac(hc->mac, pw, pwl, pmac, n1, enc, &n2);
		mac(hc->mac, pw, pwl, enc, n2, dec, &n3);
		hl_hkdf_sha256(enc, n2, hc->session_key, 64, (const hl_u8 *)"hope-chacha-encode", 18, hc->key_in, 32);
		hl_hkdf_sha256(dec, n3, hc->session_key, 64, (const hl_u8 *)"hope-chacha-decode", 18, hc->key_out, 32);
		hc->aead = TRUE;
		hc->first_sealed = TRUE;
		hc->ctr_in = hc->ctr_out = 0;
	}
}

static void hl_handshake_done(HlConn *hc)
{
	HlBuilder b;
	if (hc->legacy) {
		/* The old sign-in: login and password only inverted. */
		const char *login = purple_account_get_username(hc->account);
		const char *password = purple_connection_get_password(hc->gc);
		gsize i, n;
		guint8 *x;
		hl_b_init(&b);
		n = strlen(login);
		x = g_malloc(n + 1);
		for (i = 0; i < n; i++)
			x[i] = (guint8)~login[i];
		hl_b_bytes(&b, HL_F_USER_LOGIN, x, n);
		g_free(x);
		n = strlen(password);
		x = g_malloc(n + 1);
		for (i = 0; i < n; i++)
			x[i] = (guint8)~password[i];
		hl_b_bytes(&b, HL_F_USER_PASSWORD, x, n);
		g_free(x);
		add_login_fields(hc, &b);
		hc->stage = ST_LOGIN;
		hl_send(hc, HL_TX_LOGIN, &b, login_reply, NULL, NULL);
		return;
	}
	{
		/* Step 1 of HOPE: identification, offering what we can do. */
		static const char *const macs[] = { "HMAC-SHA256", "HMAC-SHA1", "INVERSE" };
		static const char *const cipher[] = { "CHACHA20-POLY1305" };
		guint8 zero = 0;
		hl_b_init(&b);
		hl_b_bytes(&b, HL_F_USER_LOGIN, &zero, 1);
		hl_b_bytes(&b, HL_F_USER_PASSWORD, &zero, 1);
		hl_b_name_list(&b, HL_F_HOPE_MAC_ALGORITHM, macs, 3);
		hl_b_bytes(&b, HL_F_HOPE_APP_ID, HL_APP_ID, 4);
		hl_b_str(&b, HL_F_HOPE_APP_STRING, HL_APP_STRING);
		hl_b_bytes(&b, HL_F_HOPE_SESSION_KEY, NULL, 0);
		hl_b_name_list(&b, HL_F_HOPE_CLIENT_CIPHER, cipher, 1);
		hc->stage = ST_IDENT;
		hl_send(hc, HL_TX_LOGIN, &b, hope_reply, NULL, NULL);
	}
}

/* ------------------------------------------------------------------ input */

/* Turns the socket's bytes into transaction bytes; FALSE when it needs more. */
static gboolean hl_unframe(HlConn *hc)
{
	guint32 len;
	guint8 *plain;
	hl_u8 n[12];

	if (!hc->aead) {
		if (hc->in->len == 0)
			return FALSE;
		g_byte_array_append(hc->plain, hc->in->data, hc->in->len);
		g_byte_array_set_size(hc->in, 0);
		return TRUE;
	}
	if (hc->in->len < 4)
		return FALSE;
	if (hc->first_sealed && hc->plain->len == 0 && hc->in->data[0] == 0 && hc->in->data[1] == 1) {
		/* A server that refused the login answers in the clear: a header opening 00 01. */
		hc->aead = FALSE;
		hc->first_sealed = FALSE;
		return hl_unframe(hc);
	}
	len = ((guint32)hc->in->data[0] << 24) | ((guint32)hc->in->data[1] << 16) |
	      ((guint32)hc->in->data[2] << 8) | hc->in->data[3];
	if (len < 16 || len > HL_MAX_TXN) {
		hl_error(hc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
		                               "The server sent something that isn't a Hotline frame.");
		return FALSE;
	}
	if (hc->in->len < 4 + len)
		return FALSE;
	plain = g_malloc(len);
	nonce(n, 0x00, hc->ctr_in++);
	if (hl_aead_open(hc->key_in, n, hc->in->data + 4, len, plain) != 0) {
		g_free(plain);
		hl_error(hc, PURPLE_CONNECTION_ERROR_ENCRYPTION_ERROR,
		                               hc->stage == ST_LOGIN ? "Incorrect login."
		                                                     : "A message failed its encryption check.");
		return FALSE;
	}
	hc->first_sealed = FALSE;
	g_byte_array_append(hc->plain, plain, len - 16);
	g_free(plain);
	g_byte_array_remove_range(hc->in, 0, 4 + len);
	return TRUE;
}

/* Takes one whole transaction off the front of `plain`, joining a split one. */
static HlTxn *hl_next_txn(HlConn *hc, gboolean *bad)
{
	guint32 total, part, got = 0;
	gsize off = HL_HEADER_LEN;
	GByteArray *payload;
	HlTxn *t;

	*bad = FALSE;
	if (hc->plain->len < HL_HEADER_LEN)
		return NULL;
	hl_header_sizes(hc->plain->data, &total, &part);
	if (total > HL_MAX_TXN || part > HL_MAX_TXN) {
		*bad = TRUE;
		return NULL;
	}
	payload = g_byte_array_new();
	for (;;) {
		if (hc->plain->len < off + part) {
			g_byte_array_free(payload, TRUE);
			return NULL;
		}
		g_byte_array_append(payload, hc->plain->data + off, part);
		off += part;
		got += part;
		if (got >= total)
			break;
		/* the next part: another header of the same transaction */
		if (hc->plain->len < off + HL_HEADER_LEN) {
			g_byte_array_free(payload, TRUE);
			return NULL;
		}
		{
			guint32 t2;
			hl_header_sizes(hc->plain->data + off, &t2, &part);
		}
		off += HL_HEADER_LEN;
		if (part == 0 || got + part > HL_MAX_TXN) {
			g_byte_array_free(payload, TRUE);
			*bad = TRUE;
			return NULL;
		}
	}
	t = hl_txn_parse(hc->plain->data, payload->data, payload->len);
	g_byte_array_free(payload, TRUE);
	g_byte_array_remove_range(hc->plain, 0, (guint)off);
	if (!t)
		*bad = TRUE;
	return t;
}

static void hl_read_cb(gpointer data, gint source, PurpleInputCondition cond)
{
	HlConn *hc = (HlConn *)data;
	PurpleConnection *gc = hc->gc;
	guint8 buf[8192];
	ssize_t n = read(hc->fd, buf, sizeof buf);

	if (hc->dead)
		return;
	if (n < 0 && (errno == EAGAIN || errno == EINTR))
		return;
	if (n <= 0) {
		hl_error(hc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
		                               "The server closed the connection.");
		return;
	}
	g_byte_array_append(hc->in, buf, (guint)n);

	if (hc->stage == ST_HANDSHAKE) {
		guint32 code;
		if (hc->in->len < 8)
			return;
		if (memcmp(hc->in->data, "TRTP", 4) != 0) {
			hl_error(hc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
			                               "That isn't a Hotline server.");
			return;
		}
		code = ((guint32)hc->in->data[4] << 24) | ((guint32)hc->in->data[5] << 16) |
		       ((guint32)hc->in->data[6] << 8) | hc->in->data[7];
		g_byte_array_remove_range(hc->in, 0, 8);
		if (code != 0) {
			hl_error(hc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
			                               "The server refused the connection.");
			return;
		}
		purple_connection_update_progress(gc, "Signing in", 2, 4);
		hl_handshake_done(hc);
	}

	/* A step may report an error (signing off comes later) or start over. */
	while (!hc->dead && hc->fd == source && hc->stage != ST_HANDSHAKE) {
		gboolean bad;
		HlTxn *t;
		gboolean more = hl_unframe(hc);
		if (hc->dead)
			return;
		t = hl_next_txn(hc, &bad);
		if (bad) {
			hl_error(hc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
			                               "The server sent a broken transaction.");
			return;
		}
		if (!t) {
			if (!more)
				return;
			continue;
		}
		if (t->is_reply) {
			HlPending *p = (HlPending *)g_hash_table_lookup(hc->pending, GUINT_TO_POINTER(t->id));
			if (p) {
				/* Taken out first: the callback may send more, or sign off. */
				g_hash_table_steal(hc->pending, GUINT_TO_POINTER(t->id));
				p->cb(hc, t, p->data);
				pending_free(p);
			}
		} else {
			hl_dispatch(hc, t);
		}
		hl_txn_free(t);
	}
}

static void hl_connected(gpointer data, gint source, const gchar *error)
{
	PurpleConnection *gc = (PurpleConnection *)data;
	HlConn *hc;
	int on = 1;


	if (!g_list_find(purple_connections_get_all(), gc)) {
		if (source >= 0)
			close(source);
		return;
	}
	hc = (HlConn *)gc->proto_data;
	hc->connect_data = NULL;
	if (source < 0) {
		char *msg = g_strdup_printf("Couldn't reach the server: %s", error ? error : "no answer");
		hl_error(hc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, msg);
		g_free(msg);
		return;
	}
	hc->fd = source;
	setsockopt(source, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof on);
	hc->read_h = purple_input_add(source, PURPLE_INPUT_READ, hl_read_cb, hc);
	/* TRTP handshake (guide §4.3): the sub-protocol is HOTL, version 1. */
	hl_write_raw(hc, (const guint8 *)"TRTPHOTL\0\1\0\0", 12);
}

/* Drops the socket and everything about it (keeping the connection itself). */
static void hl_drop_socket(HlConn *hc)
{
	if (hc->connect_data) {
		purple_proxy_connect_cancel(hc->connect_data);
		hc->connect_data = NULL;
	}
	if (hc->read_h)
		purple_input_remove(hc->read_h);
	if (hc->write_h)
		purple_input_remove(hc->write_h);
	hc->read_h = hc->write_h = 0;
	if (hc->fd >= 0)
		close(hc->fd);
	hc->fd = -1;
	g_byte_array_set_size(hc->in, 0);
	g_byte_array_set_size(hc->plain, 0);
	g_byte_array_set_size(hc->out, 0);
	g_hash_table_remove_all(hc->pending);
	hc->aead = hc->first_sealed = FALSE;
}

static void hl_connect(HlConn *hc)
{
	PurpleAccount *a = hc->account;
	hl_drop_socket(hc);
	hc->stage = ST_HANDSHAKE;
	hc->next_id = 1;
	hc->connect_data = purple_proxy_connect(hc->gc, a,
		purple_account_get_string(a, "server", HL_DEFAULT_SERVER),
		purple_account_get_int(a, "port", HL_DEFAULT_PORT),
		hl_connected, hc->gc);
	if (!hc->connect_data)
		hl_error(hc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
		                               "Couldn't start connecting.");
}

/* ------------------------------------------------------------------ buddies */

static const char *status_id(guint32 presence)
{
	switch (presence) {
	case P_ONLINE: return "available";
	case P_AWAY: return "away";
	case P_BUSY: return "busy";
	default: return "offline";
	}
}

static const char *local_alias(PurpleBuddy *b)
{
#if PURPLE_VERSION_CHECK(2, 6, 0)
	return purple_buddy_get_local_buddy_alias(b);
#else
	return b->alias;
#endif
}

static PurpleBuddy *ensure_buddy(HlConn *hc, const char *login)
{
	PurpleBuddy *b = purple_find_buddy(hc->account, login);
	if (!b) {
		PurpleGroup *g = purple_find_group(HL_GROUP);
		if (!g) {
			g = purple_group_new(HL_GROUP);
			purple_blist_add_group(g, NULL);
		}
		b = purple_buddy_new(hc->account, login, NULL);
		purple_blist_add_buddy(b, NULL, g, NULL);
	}
	return b;
}

static void icon_reply(HlConn *hc, HlTxn *r, gpointer data)
{
	char *login = (char *)data;
	const HlField *pic = hl_txn_get(r, HL_F_BUDDY_ICON);
	const HlField *hash = hl_txn_get(r, HL_F_BUDDY_ICON_HASH);
	if (r->error == 0 && pic && pic->len > 0 && hash && hash->len > 0) {
		char *sum = hl_hex(hash->data, hash->len);
		purple_buddy_icons_set_for_user(hc->account, login, copy_bytes(pic->data, pic->len), pic->len, sum);
		g_free(sum);
	}
}

/* Their icon by its hash: fetched when it changed, cleared when they have none. */
static void update_icon(HlConn *hc, const char *login, const HlField *hash)
{
	PurpleBuddy *b = purple_find_buddy(hc->account, login);
	const char *have;
	char *want;
	if (!b || !hc->icons)
		return;
	have = purple_buddy_icons_get_checksum_for_user(b);
	if (!hash || hash->len == 0) {
		if (have)
			purple_buddy_icons_set_for_user(hc->account, login, NULL, 0, NULL);
		return;
	}
	want = hl_hex(hash->data, hash->len);
	if (!have || strcmp(have, want) != 0) {
		HlBuilder q;
		hl_b_init(&q);
		hl_b_text(hc, &q, HL_F_FRIEND_LOGIN, login);
		hl_send(hc, HL_TX_GET_BUDDY_ICON, &q, icon_reply, g_strdup(login), g_free);
	}
	g_free(want);
}

static void set_presence_of(HlConn *hc, const char *login, guint32 presence, const char *text)
{
	if (blank(text))
		purple_prpl_got_user_status(hc->account, login, status_id(presence), NULL);
	else
		purple_prpl_got_user_status(hc->account, login, status_id(presence), "message", text, NULL);
}

typedef struct {
	PurpleAccount *account;
	char *login;
} HlAsk;

static void ask_free(HlAsk *a)
{
	g_free(a->login);
	g_free(a);
}

static HlConn *conn_of(PurpleAccount *a)
{
	PurpleConnection *gc = purple_account_get_connection(a);
	if (!gc || !g_list_find(purple_connections_get_all(), gc) ||
	    purple_connection_get_state(gc) != PURPLE_CONNECTED)
		return NULL;
	return (HlConn *)gc->proto_data;
}

static void respond(HlAsk *a, gboolean accept)
{
	HlConn *hc = conn_of(a->account);
	if (hc) {
		HlBuilder b;
		hl_b_init(&b);
		hl_b_text(hc, &b, HL_F_FRIEND_LOGIN, a->login);
		if (accept)
			hl_b_u16(&b, HL_F_ROSTER_STATE, R_ACCEPTED);
		hl_send(hc, HL_TX_FRIEND_RESPONSE, &b, NULL, NULL, NULL);
		g_hash_table_remove(hc->asked, a->login);
	}
	ask_free(a);
}

static void ask_accept(void *data) { respond((HlAsk *)data, TRUE); }
static void ask_decline(void *data) { respond((HlAsk *)data, FALSE); }

static void ask_about(HlConn *hc, const char *login, const char *name, const char *note)
{
	HlAsk *a;
	if (g_hash_table_lookup(hc->asked, login))
		return;   /* already on screen */
	g_hash_table_insert(hc->asked, g_strdup(login), GINT_TO_POINTER(1));
	a = g_new0(HlAsk, 1);
	a->account = hc->account;
	a->login = g_strdup(login);
	purple_account_request_authorization(hc->account, login, NULL, name, blank(note) ? NULL : note,
	                                     purple_find_buddy(hc->account, login) != NULL,
	                                     ask_accept, ask_decline, a);
}

/* One roster entry (fields from `from` up to the next DATA_FRIEND_LOGIN). */
static void roster_entry(HlConn *hc, const HlTxn *t, guint from, guint to)
{
	char *login = NULL, *nick = NULL, *name = NULL, *status = NULL;
	guint32 state = R_ACCEPTED, presence = P_OFFLINE;
	const HlField *hash = NULL;
	guint i;
	PurpleBuddy *b;

	for (i = from; i < to; i++) {
		const HlField *f = &t->fields[i];
		switch (f->id) {
		case HL_F_FRIEND_LOGIN: if (!login) login = hl_field_str(hc, f); break;
		case HL_F_FRIEND_NICKNAME: g_free(nick); nick = hl_field_str(hc, f); break;
		case HL_F_USER_NAME: g_free(name); name = hl_field_str(hc, f); break;
		case HL_F_ROSTER_STATE: state = hl_field_uint(f); break;
		case HL_F_PRESENCE_STATE: presence = hl_field_uint(f); break;
		case HL_F_PRESENCE_STATUS_TEXT: g_free(status); status = hl_field_str(hc, f); break;
		case HL_F_BUDDY_ICON_HASH: hash = f; break;
		}
	}
	if (blank(login))
		goto done;
	g_hash_table_insert(hc->roster, g_strdup(login), GINT_TO_POINTER(state));

	switch (state) {
	case R_ACCEPTED:
	case R_PENDING_OUT:
		b = ensure_buddy(hc, login);
		if (!blank(name))
			serv_got_alias(hc->gc, login, name);
		if (!blank(nick) && !same(local_alias(b), nick))
			purple_blist_alias_buddy(b, nick);
		if (state == R_PENDING_OUT)
			set_presence_of(hc, login, P_OFFLINE, "Waiting for them to accept your buddy request");
		else
			set_presence_of(hc, login, presence, status);
		update_icon(hc, login, hash);
		purple_privacy_deny_remove(hc->account, login, TRUE);
		break;
	case R_PENDING_IN:
		ask_about(hc, login, name, NULL);
		break;
	case R_BLOCKED:
		purple_privacy_deny_add(hc->account, login, TRUE);
		break;
	default:   /* removed */
		b = purple_find_buddy(hc->account, login);
		if (b)
			purple_blist_remove_buddy(b);
	}
done:
	g_free(login);
	g_free(nick);
	g_free(name);
	g_free(status);
}

/* The entries of a roster transaction, each opened by DATA_FRIEND_LOGIN (guide §5.5). */
static void roster_entries(HlConn *hc, const HlTxn *t)
{
	guint i, start = t->nfields;
	for (i = 0; i < t->nfields; i++) {
		if (t->fields[i].id == HL_F_FRIEND_LOGIN) {
			if (start < i)
				roster_entry(hc, t, start, i);
			start = i;
		}
	}
	if (start < t->nfields)
		roster_entry(hc, t, start, t->nfields);
}

/* Buddies kept on this computer that the server no longer lists go away. */
static void tidy_local_list(HlConn *hc)
{
	GSList *buddies = purple_find_buddies(hc->account, NULL), *l;
	for (l = buddies; l; l = l->next) {
		PurpleBuddy *b = (PurpleBuddy *)l->data;
		if (!g_hash_table_lookup(hc->roster, purple_buddy_get_name(b)))
			purple_blist_remove_buddy(b);
	}
	g_slist_free(buddies);
}

static void roster_reply(HlConn *hc, HlTxn *r, gpointer data)
{
	if (r->error != 0) {
		purple_notify_error(hc->gc, "Hotline", "Your Buddy List couldn't be loaded.", NULL);
		return;
	}
	g_hash_table_remove_all(hc->roster);
	roster_entries(hc, r);
	tidy_local_list(hc);
}

/* ------------------------------------------------------------------ status */

static guint32 presence_of_status(PurpleStatus *status, char **text)
{
	const char *id = purple_status_get_id(status);
	const char *msg = purple_status_get_attr_string(status, "message");
	*text = msg ? purple_markup_strip_html(msg) : g_strdup("");
	if (!strcmp(id, "away"))
		return P_AWAY;
	if (!strcmp(id, "busy"))
		return P_BUSY;
	if (!strcmp(id, "invisible"))
		return P_INVISIBLE;
	return P_ONLINE;
}

static void send_presence(HlConn *hc, PurpleStatus *status)
{
	char *text;
	guint32 p = presence_of_status(status, &text);
	HlBuilder b;
	hl_b_init(&b);
	hl_b_u16(&b, HL_F_PRESENCE_STATE, (guint16)p);
	/* Always sent: empty clears it (guide §11.1). */
	hl_b_text(hc, &b, HL_F_PRESENCE_STATUS_TEXT, text);
	hl_send(hc, HL_TX_SET_PRESENCE, &b, NULL, NULL, NULL);
	g_free(text);
}

static void hl_after_login(HlConn *hc, HlTxn *r)
{
	guint32 caps = 0, v;
	HlBuilder b;

	hl_txn_uint(r, HL_F_CAPABILITIES, &caps);
	hc->utf8 = (caps & HL_CAP_TEXT_ENCODING) != 0;
	if (!(caps & HL_CAP_MESSAGING)) {
		hl_error(hc, PURPLE_CONNECTION_ERROR_OTHER_ERROR,
			"This Hotline server doesn't have instant messaging (the messaging extension).");
		return;
	}
	hc->max_message = hl_txn_uint(r, HL_F_MAX_MESSAGE_BYTES, &v) && v ? v : 4096;
	hc->icons = hl_txn_uint(r, HL_F_MAX_ICON_BYTES, &v);
	hc->max_icon_bytes = hc->icons ? (v ? MIN(v, 65535) : 16384) : 0;
	hc->stage = ST_ONLINE;
	purple_connection_set_state(hc->gc, PURPLE_CONNECTED);
	DBG("signed on (%s, max message %u bytes%s)\n", hc->aead ? "encrypted" : "not encrypted",
	    hc->max_message, hc->icons ? ", buddy icons" : "");

	send_presence(hc, purple_account_get_active_status(hc->account));
	/* The readiness signal: roster, pending requests, then the offline backlog. */
	hl_b_init(&b);
	hl_send(hc, HL_TX_GET_ROSTER, &b, roster_reply, NULL, NULL);

	/* Our icon, if one is set here and the server keeps them. */
#if PURPLE_VERSION_CHECK(2, 5, 0)
	if (hc->icons) {
		PurpleStoredImage *img = purple_buddy_icons_find_account_icon(hc->account);
		if (img) {
			HlBuilder q;
			if (purple_imgstore_get_size(img) <= hc->max_icon_bytes) {
				hl_b_init(&q);
				hl_b_bytes(&q, HL_F_BUDDY_ICON, purple_imgstore_get_data(img), purple_imgstore_get_size(img));
				hl_send(hc, HL_TX_SET_BUDDY_ICON, &q, NULL, NULL, NULL);
			}
			purple_imgstore_unref(img);
		}
	}
#endif
}

/* ------------------------------------------------------------------ notifications */

static void ack(HlConn *hc, const HlField *guid, const char *from, guint16 kind)
{
	HlBuilder b;
	hl_b_init(&b);
	hl_b_bytes(&b, HL_F_MESSAGE_GUID, guid->data, guid->len);
	hl_b_u16(&b, HL_F_ACK_TYPE, kind);
	hl_b_text(hc, &b, HL_F_FRIEND_LOGIN, from);
	hl_send(hc, HL_TX_IM_ACK, &b, NULL, NULL, NULL);
}

static void agreed_reply(HlConn *hc, HlTxn *r, gpointer data)
{
	/* Nothing to do: agreements are accepted without showing them, as HIM does. */
}

static void hl_dispatch(HlConn *hc, HlTxn *t)
{
	switch (t->type) {
	case HL_TX_ROSTER_ENTRY:
		roster_entries(hc, t);
		break;
	case HL_TX_FRIEND_REQUEST: {
		char *login = hl_field_str(hc, hl_txn_get(t, HL_F_FRIEND_LOGIN));
		char *note = hl_field_str(hc, hl_txn_get(t, HL_F_REQUEST_NOTE));
		char *name = hl_field_str(hc, hl_txn_get(t, HL_F_USER_NAME));
		if (!blank(login))
			ask_about(hc, login, name, note);
		g_free(login);
		g_free(note);
		g_free(name);
		break;
	}
	case HL_TX_PRESENCE_CHANGED: {
		char *login = hl_field_str(hc, hl_txn_get(t, HL_F_FRIEND_LOGIN));
		char *text = hl_field_str(hc, hl_txn_get(t, HL_F_PRESENCE_STATUS_TEXT));
		char *name = hl_field_str(hc, hl_txn_get(t, HL_F_USER_NAME));
		guint32 p = P_OFFLINE;
		hl_txn_uint(t, HL_F_PRESENCE_STATE, &p);
		if (!blank(login) && purple_find_buddy(hc->account, login)) {
			/* Status and icon are complete in each 809; the name is kept when absent. */
			if (!blank(name))
				serv_got_alias(hc->gc, login, name);
			set_presence_of(hc, login, p, text);
			update_icon(hc, login, hl_txn_get(t, HL_F_BUDDY_ICON_HASH));
		}
		g_free(login);
		g_free(text);
		g_free(name);
		break;
	}
	case HL_TX_IM_DELIVER: {
		const HlField *guid = hl_txn_get(t, HL_F_MESSAGE_GUID);
		char *from = hl_field_str(hc, hl_txn_get(t, HL_F_FRIEND_LOGIN));
		char *body = hl_field_str(hc, hl_txn_get(t, HL_F_MESSAGE_BODY));
		guint32 ts = 0;
		time_t when = time(NULL);
		PurpleMessageFlags flags = PURPLE_MESSAGE_RECV;
		if (guid && !blank(from)) {
			char *html = purple_markup_escape_text(body ? body : "", -1);
			char *br = purple_strdup_withhtml(html);
			ack(hc, guid, from, 1);   /* delivered */
			if (hl_txn_uint(t, HL_F_MESSAGE_TIMESTAMP, &ts) && ts > 0) {
				if ((time_t)ts < when - 60)
					flags |= PURPLE_MESSAGE_DELAYED;   /* held while we were away */
				when = (time_t)ts;
			}
			serv_got_typing_stopped(hc->gc, from);
			serv_got_im(hc->gc, from, br, flags, when);
			g_free(html);
			g_free(br);
		}
		g_free(from);
		g_free(body);
		break;
	}
	case HL_TX_IM_TYPING: {
		char *from = hl_field_str(hc, hl_txn_get(t, HL_F_FRIEND_LOGIN));
		guint32 typing = 0;
		hl_txn_uint(t, HL_F_TYPING_STATE, &typing);
		if (!blank(from)) {
			if (typing == 1)
				serv_got_typing(hc->gc, from, 15, PURPLE_TYPING);
			else
				serv_got_typing_stopped(hc->gc, from);
		}
		g_free(from);
		break;
	}
	case HL_TX_SHOW_AGREEMENT: {
		guint32 none = 0;
		if (!(hl_txn_uint(t, HL_F_NO_AGREEMENT, &none) && none == 1)) {
			HlBuilder b;
			const char *nick = purple_account_get_alias(hc->account);
			hl_b_init(&b);
			hl_b_text(hc, &b, HL_F_USER_NAME, blank(nick) ? purple_account_get_username(hc->account) : nick);
			hl_b_int(&b, HL_F_USER_ICON_ID, 0);
			hl_b_int(&b, HL_F_OPTIONS, 0);
			hl_send(hc, HL_TX_AGREED, &b, agreed_reply, NULL, NULL);
		}
		break;
	}
	case HL_TX_SERVER_MSG: {
		guint32 uid;
		char *text = hl_field_str(hc, hl_txn_get(t, HL_F_DATA));
		if (!hl_txn_uint(t, HL_F_USER_ID, &uid) && !blank(text))
			purple_notify_info(hc->gc, "Hotline", "Message from the server", text);
		g_free(text);
		break;
	}
	case HL_TX_DISCONNECT_MSG: {
		char *text = hl_field_str(hc, hl_txn_get(t, HL_F_DATA));
		hl_error(hc, PURPLE_CONNECTION_ERROR_OTHER_ERROR,
		                               blank(text) ? "The server disconnected you." : text);
		g_free(text);
		break;
	}
	case HL_TX_SET_BUDDY_ICON:
		/* Another of our sessions changed our icon; this one keeps its own. */
		break;
	default:
		break;   /* unknown notifications are ignored (guide §5.2) */
	}
}

/* ------------------------------------------------------------------ prpl callbacks */

static const char *hl_list_icon(PurpleAccount *a, PurpleBuddy *b)
{
	return "hotline";
}

static char *hl_status_text(PurpleBuddy *b)
{
	PurplePresence *p = purple_buddy_get_presence(b);
	PurpleStatus *s = purple_presence_get_active_status(p);
	const char *msg = purple_status_get_attr_string(s, "message");
	return blank(msg) ? NULL : g_markup_escape_text(msg, -1);
}

static void hl_tooltip_text(PurpleBuddy *b, PurpleNotifyUserInfo *info, gboolean full)
{
	PurplePresence *p = purple_buddy_get_presence(b);
	PurpleStatus *s = purple_presence_get_active_status(p);
	const char *msg = purple_status_get_attr_string(s, "message");
	purple_notify_user_info_add_pair(info, "Status", purple_status_get_name(s));
	if (!blank(msg))
		purple_notify_user_info_add_pair(info, "Message", msg);
}

static GList *hl_status_types(PurpleAccount *a)
{
	GList *types = NULL;
	types = g_list_append(types, purple_status_type_new_with_attrs(PURPLE_STATUS_AVAILABLE, "available", NULL,
		TRUE, TRUE, FALSE, "message", "Message", purple_value_new(PURPLE_TYPE_STRING), NULL));
	types = g_list_append(types, purple_status_type_new_with_attrs(PURPLE_STATUS_AWAY, "away", NULL,
		TRUE, TRUE, FALSE, "message", "Message", purple_value_new(PURPLE_TYPE_STRING), NULL));
	types = g_list_append(types, purple_status_type_new_with_attrs(PURPLE_STATUS_UNAVAILABLE, "busy", "Busy",
		TRUE, TRUE, FALSE, "message", "Message", purple_value_new(PURPLE_TYPE_STRING), NULL));
	types = g_list_append(types, purple_status_type_new_full(PURPLE_STATUS_INVISIBLE, "invisible", NULL,
		TRUE, TRUE, FALSE));
	types = g_list_append(types, purple_status_type_new_full(PURPLE_STATUS_OFFLINE, "offline", NULL,
		TRUE, TRUE, FALSE));
	return types;
}

static void hl_login(PurpleAccount *account)
{
	PurpleConnection *gc = purple_account_get_connection(account);
	HlConn *hc = g_new0(HlConn, 1);
	hc->gc = gc;
	hc->account = account;
	hc->fd = -1;
	hc->in = g_byte_array_new();
	hc->plain = g_byte_array_new();
	hc->out = g_byte_array_new();
	hc->pending = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, pending_free);
	hc->asked = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
	hc->roster = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
	hc->utf8 = TRUE;
	hc->max_message = 4096;
	gc->proto_data = hc;
	gc->flags |= PURPLE_CONNECTION_NO_BGCOLOR | PURPLE_CONNECTION_NO_FONTSIZE | PURPLE_CONNECTION_NO_URLDESC |
	             PURPLE_CONNECTION_NO_IMAGES;
	purple_connection_update_progress(gc, "Connecting", 1, 4);
	hl_connect(hc);
}

static void hl_close(PurpleConnection *gc)
{
	HlConn *hc = (HlConn *)gc->proto_data;
	if (!hc)
		return;
	if (hc->fd >= 0 && hc->stage == ST_ONLINE)
		hl_flush(hc);   /* last words (a presence change, say) */
	hl_drop_socket(hc);
	g_byte_array_free(hc->in, TRUE);
	g_byte_array_free(hc->plain, TRUE);
	g_byte_array_free(hc->out, TRUE);
	g_hash_table_destroy(hc->pending);
	g_hash_table_destroy(hc->asked);
	g_hash_table_destroy(hc->roster);
	g_free(hc);
	gc->proto_data = NULL;
}

typedef struct {
	PurpleAccount *account;
	char *who;
} HlImWho;

static void imwho_free(gpointer p)
{
	HlImWho *w = (HlImWho *)p;
	g_free(w->who);
	g_free(w);
}

static void im_reply(HlConn *hc, HlTxn *r, gpointer data)
{
	HlImWho *w = (HlImWho *)data;
	guint32 reason = 0;
	hl_txn_uint(r, HL_F_REASON_CODE, &reason);
	if (r->error != 0) {
		char *why = reply_error(hc, r);
		purple_conv_present_error(w->who, w->account, why);
		g_free(why);
	} else if (reason == HL_REASON_OFFLINE_QUEUED) {
		PurpleConversation *c = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, w->who, w->account);
		if (c)
			purple_conversation_write(c, NULL, "They're away from the keyboard; it will be delivered when they're back.",
			                          PURPLE_MESSAGE_SYSTEM | PURPLE_MESSAGE_NO_LOG, time(NULL));
	}
}

static int hl_send_im(PurpleConnection *gc, const char *who, const char *message, PurpleMessageFlags flags)
{
	HlConn *hc = (HlConn *)gc->proto_data;
	char *text = purple_markup_strip_html(message);
	char *wire;
	gsize len;
	guint8 guid[16];
	HlBuilder b;
	HlImWho *w;

	wire = hl_encode(hc, text, &len);
	g_free(text);
	if (len > hc->max_message || len > 0xFFFF) {
		g_free(wire);
		return -E2BIG;
	}
	if (hl_random(guid, sizeof guid) != 0) {
		g_free(wire);
		return -EIO;
	}
	guid[6] = (guint8)((guid[6] & 0x0F) | 0x40);   /* a version 4 UUID */
	guid[8] = (guint8)((guid[8] & 0x3F) | 0x80);
	hl_b_init(&b);
	hl_b_text(hc, &b, HL_F_FRIEND_LOGIN, who);
	hl_b_bytes(&b, HL_F_MESSAGE_GUID, guid, 16);
	hl_b_bytes(&b, HL_F_MESSAGE_BODY, wire, len);
	g_free(wire);
	w = g_new0(HlImWho, 1);
	w->account = hc->account;
	w->who = g_strdup(who);
	hl_send(hc, HL_TX_IM_SEND, &b, im_reply, w, imwho_free);
	return 1;
}

static unsigned int hl_send_typing(PurpleConnection *gc, const char *who, PurpleTypingState state)
{
	HlConn *hc = (HlConn *)gc->proto_data;
	HlBuilder b;
	if (!hc || hc->stage != ST_ONLINE)
		return 0;
	hl_b_init(&b);
	hl_b_text(hc, &b, HL_F_FRIEND_LOGIN, who);
	hl_b_u16(&b, HL_F_TYPING_STATE, state == PURPLE_TYPING ? 1 : 0);
	hl_send(hc, HL_TX_IM_TYPING, &b, NULL, NULL, NULL);
	return 0;
}

static void hl_set_status(PurpleAccount *account, PurpleStatus *status)
{
	HlConn *hc = conn_of(account);
	if (hc && purple_status_is_active(status))
		send_presence(hc, status);
}

static void simple_reply(HlConn *hc, HlTxn *r, gpointer data)
{
	if (r->error != 0) {
		char *why = reply_error(hc, r);
		purple_notify_error(hc->gc, "Hotline", (const char *)data, why);
		g_free(why);
	}
}

static void hl_add_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group)
{
	HlConn *hc = (HlConn *)gc->proto_data;
	HlBuilder b;
	hl_b_init(&b);
	hl_b_text(hc, &b, HL_F_FRIEND_LOGIN, purple_buddy_get_name(buddy));
	hl_send(hc, HL_TX_ADD_FRIEND, &b, simple_reply, (gpointer)"Your buddy request didn't go.", NULL);
	purple_prpl_got_user_status(hc->account, purple_buddy_get_name(buddy), "offline",
	                            "message", "Waiting for them to accept your buddy request", NULL);
}

static void hl_remove_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group)
{
	HlConn *hc = (HlConn *)gc->proto_data;
	HlBuilder b;
	if (!hc || hc->stage != ST_ONLINE)
		return;
	hl_b_init(&b);
	hl_b_text(hc, &b, HL_F_FRIEND_LOGIN, purple_buddy_get_name(buddy));
	hl_send(hc, HL_TX_REMOVE_FRIEND, &b, NULL, NULL, NULL);
	g_hash_table_remove(hc->roster, purple_buddy_get_name(buddy));
}

static void hl_alias_buddy(PurpleConnection *gc, const char *who, const char *alias)
{
	HlConn *hc = (HlConn *)gc->proto_data;
	HlBuilder b;
	hl_b_init(&b);
	hl_b_text(hc, &b, HL_F_FRIEND_LOGIN, who);
	hl_b_text(hc, &b, HL_F_FRIEND_NICKNAME, alias ? alias : "");
	hl_send(hc, HL_TX_SET_FRIEND_NICKNAME, &b, NULL, NULL, NULL);
}

static void block(PurpleConnection *gc, const char *who, guint16 type)
{
	HlConn *hc = (HlConn *)gc->proto_data;
	HlBuilder b;
	if (!hc || hc->stage != ST_ONLINE)
		return;
	hl_b_init(&b);
	hl_b_text(hc, &b, HL_F_FRIEND_LOGIN, who);
	hl_send(hc, type, &b, NULL, NULL, NULL);
}

static void hl_add_deny(PurpleConnection *gc, const char *who) { block(gc, who, HL_TX_BLOCK_USER); }
static void hl_rem_deny(PurpleConnection *gc, const char *who) { block(gc, who, HL_TX_UNBLOCK_USER); }

static void info_reply(HlConn *hc, HlTxn *r, gpointer data)
{
	char *who = (char *)data;
	PurpleNotifyUserInfo *info = purple_notify_user_info_new();
	static const struct { guint16 id; const char *label; } rows[] = {
		{ HL_F_USER_NAME, "Name" },
		{ HL_F_PROFILE_NICKNAME, "Nickname" },
		{ HL_F_PROFILE_FIRST_NAME, "First name" },
		{ HL_F_PROFILE_LAST_NAME, "Last name" },
		{ HL_F_PROFILE_EMAIL, "E-mail" },
		{ HL_F_PROFILE_COUNTRY, "Country" }
	};
	guint i;
	purple_notify_user_info_add_pair(info, "Screen name", who);
	if (r->error != 0) {
		char *why = reply_error(hc, r);
		purple_notify_user_info_add_pair(info, "Profile", why);
		g_free(why);
	} else {
		for (i = 0; i < G_N_ELEMENTS(rows); i++) {
			char *v = hl_field_str(hc, hl_txn_get(r, rows[i].id));
			if (!blank(v)) {
				char *e = g_markup_escape_text(v, -1);
				purple_notify_user_info_add_pair(info, rows[i].label, e);
				g_free(e);
			}
			g_free(v);
		}
	}
	purple_notify_userinfo(hc->gc, who, info, NULL, NULL);
	purple_notify_user_info_destroy(info);
}

static void hl_get_info(PurpleConnection *gc, const char *who)
{
	HlConn *hc = (HlConn *)gc->proto_data;
	HlBuilder b;
	hl_b_init(&b);
	hl_b_text(hc, &b, HL_F_FRIEND_LOGIN, who);
	hl_send(hc, HL_TX_GET_USER_INFO, &b, info_reply, g_strdup(who), g_free);
}

static void hl_set_buddy_icon(PurpleConnection *gc, PurpleStoredImage *img)
{
	HlConn *hc = (HlConn *)gc->proto_data;
	HlBuilder b;
	if (!hc || hc->stage != ST_ONLINE || !hc->icons)
		return;
	if (img && purple_imgstore_get_size(img) > hc->max_icon_bytes) {
		purple_notify_error(gc, "Hotline", "That Buddy Icon is too big for this server.", NULL);
		return;
	}
	hl_b_init(&b);
	if (img)
		hl_b_bytes(&b, HL_F_BUDDY_ICON, purple_imgstore_get_data(img), purple_imgstore_get_size(img));
	else
		hl_b_bytes(&b, HL_F_BUDDY_ICON, NULL, 0);   /* empty clears it */
	hl_send(hc, HL_TX_SET_BUDDY_ICON, &b, simple_reply, (gpointer)"Your Buddy Icon wasn't saved.", NULL);
}

static gboolean hl_offline_message(const PurpleBuddy *buddy)
{
	return TRUE;   /* the server holds IMs for buddies who are away (guide §13) */
}

/* ------------------------------------------------------------------ plugin */

static PurplePluginProtocolInfo prpl_info = {
	.options = 0,
	.icon_spec = { "png,gif,jpeg", 0, 0, 64, 64, 65535, PURPLE_ICON_SCALE_SEND },
	.list_icon = hl_list_icon,
	.status_text = hl_status_text,
	.tooltip_text = hl_tooltip_text,
	.status_types = hl_status_types,
	.login = hl_login,
	.close = hl_close,
	.send_im = hl_send_im,
	.send_typing = hl_send_typing,
	.get_info = hl_get_info,
	.set_status = hl_set_status,
	.add_buddy = hl_add_buddy,
	.remove_buddy = hl_remove_buddy,
	.add_deny = hl_add_deny,
	.rem_deny = hl_rem_deny,
	.alias_buddy = hl_alias_buddy,
	.normalize = purple_normalize_nocase,
	.set_buddy_icon = hl_set_buddy_icon,
	.offline_message = hl_offline_message,
#if PURPLE_VERSION_CHECK(2, 5, 0)
	.struct_size = sizeof(PurplePluginProtocolInfo),
#endif
};

static PurplePluginInfo info = {
	PURPLE_PLUGIN_MAGIC,
	PURPLE_MAJOR_VERSION,
	PURPLE_MINOR_VERSION,
	PURPLE_PLUGIN_PROTOCOL,
	NULL,
	0,
	NULL,
	PURPLE_PRIORITY_DEFAULT,
	HL_PRPL_ID,
	"Hotline",
	HL_VERSION,
	"Hotline Instant Messaging",
	"Hotline buddy lists and instant messages (fogWraith's messaging extension), with HOPE "
	"secure sign-in and encryption, as in HIM.",
	"John Leighow",
	"https://github.com/tagban/purple-hotline",
	NULL,
	NULL,
	NULL,
	NULL,
	&prpl_info,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};

static void init_plugin(PurplePlugin *plugin)
{
	GList *opts = NULL;
	opts = g_list_append(opts, purple_account_option_string_new("Server", "server", HL_DEFAULT_SERVER));
	opts = g_list_append(opts, purple_account_option_int_new("Port", "port", HL_DEFAULT_PORT));
	opts = g_list_append(opts, purple_account_option_bool_new(
		"Allow sign-in without protecting the password (old servers)", "allow_legacy", FALSE));
	prpl_info.protocol_options = opts;
}

PURPLE_INIT_PLUGIN(hotline, init_plugin, info)
