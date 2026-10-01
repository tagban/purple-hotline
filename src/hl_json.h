/*
 * purple-hotline: a small JSON reader (old Mac OS X has none built in). Enough for
 * the tracker's server lists: objects, arrays, strings, numbers, true/false/null.
 *
 * Copyright (c) 2026 John Leighow. MIT license (see LICENSE).
 */
#ifndef HL_JSON_H
#define HL_JSON_H

#include <glib.h>

typedef enum { HL_JNULL, HL_JBOOL, HL_JNUM, HL_JSTR, HL_JARR, HL_JOBJ } HlJsonType;

typedef struct _HlJson HlJson;
struct _HlJson {
	HlJsonType type;
	gboolean b;
	double n;
	char *s;             /* strings (UTF-8) */
	char **keys;         /* objects: keys[i] names items[i] */
	HlJson **items;      /* arrays and objects */
	guint count;
};

/* NULL if it isn't JSON. */
HlJson *hl_json_parse(const char *text, gsize len);
void hl_json_free(HlJson *j);

/* An object's member by key, or NULL (also when `j` isn't an object). */
HlJson *hl_json_get(const HlJson *j, const char *key);
const char *hl_json_str(const HlJson *j, const char *key);   /* NULL unless a string */
double hl_json_num(const HlJson *j, const char *key, double fallback);
gboolean hl_json_bool(const HlJson *j, const char *key, gboolean fallback);

#endif
