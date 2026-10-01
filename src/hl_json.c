/*
 * purple-hotline: a small JSON reader. See hl_json.h.
 * Copyright (c) 2026 John Leighow. MIT license.
 */
#include "hl_json.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
	const char *p, *end;
	int depth;
} Reader;

static void skip_ws(Reader *r)
{
	while (r->p < r->end && (*r->p == ' ' || *r->p == '\t' || *r->p == '\n' || *r->p == '\r'))
		r->p++;
}

static HlJson *value(Reader *r);

static HlJson *node(HlJsonType t)
{
	HlJson *j = g_new0(HlJson, 1);
	j->type = t;
	return j;
}

static int hex4(const char *p)
{
	int v = 0, i;
	for (i = 0; i < 4; i++) {
		char c = p[i];
		v <<= 4;
		if (c >= '0' && c <= '9') v |= c - '0';
		else if (c >= 'a' && c <= 'f') v |= c - 'a' + 10;
		else if (c >= 'A' && c <= 'F') v |= c - 'A' + 10;
		else return -1;
	}
	return v;
}

/* After the opening quote; returns a new UTF-8 string, or NULL. */
static char *string(Reader *r)
{
	GString *out = g_string_new(NULL);
	while (r->p < r->end) {
		char c = *r->p++;
		if (c == '"')
			return g_string_free(out, FALSE);
		if ((unsigned char)c < 0x20)
			break;
		if (c != '\\') {
			g_string_append_c(out, c);
			continue;
		}
		if (r->p >= r->end)
			break;
		c = *r->p++;
		switch (c) {
		case '"': case '\\': case '/': g_string_append_c(out, c); break;
		case 'b': g_string_append_c(out, '\b'); break;
		case 'f': g_string_append_c(out, '\f'); break;
		case 'n': g_string_append_c(out, '\n'); break;
		case 'r': g_string_append_c(out, '\r'); break;
		case 't': g_string_append_c(out, '\t'); break;
		case 'u': {
			int cp;
			if (r->end - r->p < 4 || (cp = hex4(r->p)) < 0)
				goto bad;
			r->p += 4;
			/* a surrogate pair makes one character beyond the BMP */
			if (cp >= 0xD800 && cp <= 0xDBFF && r->end - r->p >= 6 && r->p[0] == '\\' && r->p[1] == 'u') {
				int lo = hex4(r->p + 2);
				if (lo >= 0xDC00 && lo <= 0xDFFF) {
					cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
					r->p += 6;
				}
			}
			g_string_append_unichar(out, (gunichar)cp);
			break;
		}
		default:
			goto bad;
		}
	}
bad:
	g_string_free(out, TRUE);
	return NULL;
}

static HlJson *container(Reader *r, gboolean object)
{
	HlJson *j = node(object ? HL_JOBJ : HL_JARR);
	GPtrArray *keys = g_ptr_array_new(), *items = g_ptr_array_new();
	char close = object ? '}' : ']';

	if (++r->depth > 64)
		goto bad;
	skip_ws(r);
	if (r->p < r->end && *r->p == close) {
		r->p++;
		goto done;
	}
	for (;;) {
		HlJson *v;
		skip_ws(r);
		if (object) {
			char *k;
			if (r->p >= r->end || *r->p != '"')
				goto bad;
			r->p++;
			if (!(k = string(r)))
				goto bad;
			g_ptr_array_add(keys, k);
			skip_ws(r);
			if (r->p >= r->end || *r->p != ':')
				goto bad;
			r->p++;
		}
		if (!(v = value(r)))
			goto bad;
		g_ptr_array_add(items, v);
		skip_ws(r);
		if (r->p < r->end && *r->p == ',') {
			r->p++;
			continue;
		}
		if (r->p < r->end && *r->p == close) {
			r->p++;
			break;
		}
		goto bad;
	}
done:
	r->depth--;
	j->count = items->len;
	j->items = (HlJson **)g_ptr_array_free(items, FALSE);
	j->keys = object ? (char **)g_ptr_array_free(keys, FALSE) : NULL;
	if (!object)
		g_ptr_array_free(keys, TRUE);
	return j;
bad:
	{
		guint i;
		for (i = 0; i < keys->len; i++)
			g_free(g_ptr_array_index(keys, i));
		for (i = 0; i < items->len; i++)
			hl_json_free((HlJson *)g_ptr_array_index(items, i));
		g_ptr_array_free(keys, TRUE);
		g_ptr_array_free(items, TRUE);
		g_free(j);
		return NULL;
	}
}

static gboolean word(Reader *r, const char *w)
{
	size_t n = strlen(w);
	if ((size_t)(r->end - r->p) < n || strncmp(r->p, w, n) != 0)
		return FALSE;
	r->p += n;
	return TRUE;
}

static HlJson *value(Reader *r)
{
	HlJson *j;
	skip_ws(r);
	if (r->p >= r->end)
		return NULL;
	switch (*r->p) {
	case '{': r->p++; return container(r, TRUE);
	case '[': r->p++; return container(r, FALSE);
	case '"': {
		char *s;
		r->p++;
		if (!(s = string(r)))
			return NULL;
		j = node(HL_JSTR);
		j->s = s;
		return j;
	}
	case 't': if (!word(r, "true")) return NULL; j = node(HL_JBOOL); j->b = TRUE; return j;
	case 'f': if (!word(r, "false")) return NULL; return node(HL_JBOOL);
	case 'n': if (!word(r, "null")) return NULL; return node(HL_JNULL);
	default: {
		char buf[64];
		const char *start = r->p;
		size_t n;
		while (r->p < r->end && strchr("+-0123456789.eE", *r->p))
			r->p++;
		n = (size_t)(r->p - start);
		if (n == 0 || n >= sizeof buf)
			return NULL;
		memcpy(buf, start, n);
		buf[n] = 0;
		j = node(HL_JNUM);
		j->n = g_ascii_strtod(buf, NULL);
		return j;
	}
	}
}

HlJson *hl_json_parse(const char *text, gsize len)
{
	Reader r;
	HlJson *j;
	r.p = text;
	r.end = text + len;
	r.depth = 0;
	j = value(&r);
	skip_ws(&r);
	if (j && r.p != r.end) {
		hl_json_free(j);
		return NULL;
	}
	return j;
}

void hl_json_free(HlJson *j)
{
	guint i;
	if (!j)
		return;
	for (i = 0; i < j->count; i++) {
		hl_json_free(j->items[i]);
		if (j->keys)
			g_free(j->keys[i]);
	}
	g_free(j->items);
	g_free(j->keys);
	g_free(j->s);
	g_free(j);
}

HlJson *hl_json_get(const HlJson *j, const char *key)
{
	guint i;
	if (!j || j->type != HL_JOBJ)
		return NULL;
	for (i = 0; i < j->count; i++)
		if (strcmp(j->keys[i], key) == 0)
			return j->items[i];
	return NULL;
}

const char *hl_json_str(const HlJson *j, const char *key)
{
	HlJson *v = hl_json_get(j, key);
	return v && v->type == HL_JSTR ? v->s : NULL;
}

double hl_json_num(const HlJson *j, const char *key, double fallback)
{
	HlJson *v = hl_json_get(j, key);
	return v && v->type == HL_JNUM ? v->n : fallback;
}

gboolean hl_json_bool(const HlJson *j, const char *key, gboolean fallback)
{
	HlJson *v = hl_json_get(j, key);
	return v && v->type == HL_JBOOL ? v->b : fallback;
}
