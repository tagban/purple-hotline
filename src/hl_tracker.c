/*
 * purple-hotline: the public Hotline servers, from BigRedH's tracker. See hl_tracker.h.
 * Copyright (c) 2026 John Leighow. MIT license.
 */
#include "hl_tracker.h"
#include "hl_json.h"

#include <string.h>
#include <time.h>

#include "debug.h"
#include "util.h"

#define FRESH_SECS 600

/* Substrings (any case) of server names that aren't places to chat. */
static const char *const junk[] = {
	"major mac backup",
	"welcome to hotline",
	"--welcome--",
	"----",
	NULL
};

gboolean hl_server_name_is_junk(const char *name)
{
	char *lower;
	const char *p;
	gboolean letters = FALSE;
	int i;
	if (!name)
		return TRUE;
	for (p = name; *p; p++)
		if (g_ascii_isalnum(*p) || (unsigned char)*p >= 0x80)
			letters = TRUE;
	if (!letters)
		return TRUE;   /* a divider: "-----", "=====" */
	lower = g_ascii_strdown(name, -1);
	for (i = 0; junk[i]; i++) {
		if (strstr(lower, junk[i])) {
			g_free(lower);
			return TRUE;
		}
	}
	g_free(lower);
	return FALSE;
}

char *hl_server_address(const HlServer *s)
{
	return s->port == 5500 ? g_strdup(s->host) : g_strdup_printf("%s:%d", s->host, s->port);
}

static void server_free(gpointer p)
{
	HlServer *s = (HlServer *)p;
	g_free(s->host);
	g_free(s->name);
	g_free(s->description);
	g_free(s);
}

void hl_servers_free(GPtrArray *servers)
{
	guint i;
	if (!servers)
		return;
	for (i = 0; i < servers->len; i++)
		server_free(g_ptr_array_index(servers, i));
	g_ptr_array_free(servers, TRUE);
}

static int by_people(gconstpointer a, gconstpointer b)
{
	const HlServer *x = *(HlServer *const *)a, *y = *(HlServer *const *)b;
	if (x->kind != y->kind)
		return (int)x->kind - (int)y->kind;
	if (x->users != y->users)
		return y->users - x->users;
	return g_ascii_strcasecmp(x->name, y->name);
}

static char *clean(const char *s)
{
	char *c = g_strdup(s ? s : "");
	char *p;
	for (p = c; *p; p++)
		if (*p == '\r' || *p == '\n' || *p == '\t')
			*p = ' ';
	return g_strstrip(c);
}

GPtrArray *hl_tracker_parse(const char *servers_json, gsize slen, const char *live_json, gsize llen)
{
	HlJson *all = hl_json_parse(servers_json, slen);
	HlJson *live = live_json ? hl_json_parse(live_json, llen) : NULL;
	HlJson *up = hl_json_get(live, "servers");
	GPtrArray *out;
	guint i;

	if (!all || all->type != HL_JOBJ) {
		hl_json_free(all);
		hl_json_free(live);
		return NULL;
	}
	out = g_ptr_array_new();
	for (i = 0; i < all->count; i++) {
		const HlJson *e = all->items[i];
		const HlJson *state = hl_json_get(up, all->keys[i]);
		const char *host = hl_json_str(e, "host");
		int port = (int)hl_json_num(e, "port", 5500);
		HlServer *s;
		if (!host || !*host || port <= 0 || port > 65535 || strcmp(host, "0.0.0.0") == 0)
			continue;
		if (state && !hl_json_bool(state, "online", TRUE))
			continue;   /* down right now */
		s = g_new0(HlServer, 1);
		s->host = g_strdup(host);
		s->port = port;
		s->name = clean(hl_json_str(e, "name"));
		if (!*s->name) {
			g_free(s->name);
			s->name = hl_server_address(s);
		}
		s->description = clean(hl_json_str(e, "description"));
		s->users = state ? (int)hl_json_num(state, "users", -1) : -1;
		if (hl_server_name_is_junk(s->name))
			s->kind = HL_SERVER_HIDDEN;
		else if (s->users == 0)
			s->kind = HL_SERVER_QUIET;
		else
			s->kind = HL_SERVER_BUSY;
		g_ptr_array_add(out, s);
	}
	g_ptr_array_sort(out, by_people);
	hl_json_free(all);
	hl_json_free(live);
	return out;
}

/* ---- fetching (servers.json, then live.json), with a short-lived shared copy ---- */

typedef struct {
	char *base;
	char *servers_json;
	gsize slen;
	HlServersCb cb;
	gpointer data;
} Fetch;

static char *cached_servers, *cached_live, *cached_base;
static gsize cached_slen, cached_llen;
static time_t cached_at;

static GPtrArray *from_cache(void)
{
	return hl_tracker_parse(cached_servers, cached_slen, cached_live, cached_llen);
}

static void fetch_free(Fetch *f)
{
	g_free(f->base);
	g_free(f->servers_json);
	g_free(f);
}

static void got_live(PurpleUtilFetchUrlData *req, gpointer data, const gchar *text, gsize len, const gchar *error)
{
	Fetch *f = (Fetch *)data;
	GPtrArray *list;
	/* Without the live file the list still works, just without who's there. */
	if (error || !text)
		purple_debug_warning("hotline", "tracker live.json: %s\n", error ? error : "empty");
	list = hl_tracker_parse(f->servers_json, f->slen, error ? NULL : text, error ? 0 : len);
	if (!list) {
		f->cb(NULL, "The server list couldn't be read.", f->data);
	} else {
		g_free(cached_servers);
		g_free(cached_live);
		g_free(cached_base);
		cached_servers = f->servers_json;
		cached_slen = f->slen;
		f->servers_json = NULL;
		cached_live = (error || !text) ? NULL : g_strndup(text, len);
		cached_llen = cached_live ? len : 0;
		cached_base = g_strdup(f->base);
		cached_at = time(NULL);
		f->cb(list, NULL, f->data);
		hl_servers_free(list);
	}
	fetch_free(f);
}

static void got_servers(PurpleUtilFetchUrlData *req, gpointer data, const gchar *text, gsize len, const gchar *error)
{
	Fetch *f = (Fetch *)data;
	char *url;
	if (error || !text || len == 0) {
		char *msg = g_strdup_printf("The server list couldn't be loaded: %s", error ? error : "no answer");
		f->cb(NULL, msg, f->data);
		g_free(msg);
		fetch_free(f);
		return;
	}
	f->servers_json = g_strndup(text, len);
	f->slen = len;
	url = g_strconcat(f->base, "live.json", NULL);
	purple_util_fetch_url(url, FALSE, "purple-hotline", FALSE, got_live, f);
	g_free(url);
}

void hl_tracker_fetch(const char *base, HlServersCb cb, gpointer data)
{
	Fetch *f;
	char *url, *norm;
	if (!base || !*base)
		base = HL_TRACKER_URL;
	norm = g_str_has_suffix(base, "/") ? g_strdup(base) : g_strconcat(base, "/", NULL);
	if (cached_servers && cached_base && strcmp(cached_base, norm) == 0 &&
	    time(NULL) - cached_at < FRESH_SECS) {
		GPtrArray *list = from_cache();
		g_free(norm);
		cb(list, list ? NULL : "The server list couldn't be read.", data);
		hl_servers_free(list);
		return;
	}
	f = g_new0(Fetch, 1);
	f->base = norm;
	f->cb = cb;
	f->data = data;
	url = g_strconcat(f->base, "servers.json", NULL);
	purple_util_fetch_url(url, FALSE, "purple-hotline", FALSE, got_servers, f);
	g_free(url);
}
