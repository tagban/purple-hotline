/*
 * purple-hotline: the public Hotline servers, from BigRedH's tracker
 * (tracker.bigredh.com, updated hourly from github.com/Big-Red-H/bigredh): the
 * servers the trackers list, and whether each is up and how many are there.
 * Fetched over plain HTTP, so even Adium on Mac OS X 10.4 can read it.
 *
 * Copyright (c) 2026 John Leighow. MIT license (see LICENSE).
 */
#ifndef HL_TRACKER_H
#define HL_TRACKER_H

#include <glib.h>

#define HL_TRACKER_URL "http://tracker.bigredh.com/data/"

typedef enum {
	HL_SERVER_BUSY,     /* people are there */
	HL_SERVER_QUIET,    /* up, but no one's there right now */
	HL_SERVER_HIDDEN    /* file mirrors and placeholder listings, not places to chat */
} HlServerKind;

typedef struct {
	char *host;
	int port;
	char *name;
	char *description;
	int users;          /* -1 when the tracker didn't say */
	HlServerKind kind;
} HlServer;

/* `servers` holds HlServer *, busiest first; it's the caller's for this call only.
 * On failure `servers` is NULL and `error` says why. */
typedef void (*HlServersCb)(GPtrArray *servers, const char *error, gpointer data);

/* Fetches (or reuses a list under ten minutes old). `base` is the folder holding
 * servers.json and live.json; NULL for BigRedH's. */
void hl_tracker_fetch(const char *base, HlServersCb cb, gpointer data);

/* Parses the two files into a list (exposed for the tests). */
GPtrArray *hl_tracker_parse(const char *servers_json, gsize slen, const char *live_json, gsize llen);
void hl_servers_free(GPtrArray *servers);

/* Names that aren't chat places: MAJOR MAC BACKUP, Welcome to Hotline, dividers... */
gboolean hl_server_name_is_junk(const char *name);

/* "host:port" (the port left off when it's 5500). Free with g_free. */
char *hl_server_address(const HlServer *s);

#endif
