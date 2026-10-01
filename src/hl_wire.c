/*
 * purple-hotline: Hotline transactions. See hl_wire.h.
 * Copyright (c) 2026 John Leighow. MIT license.
 */
#include "hl_wire.h"

#include <string.h>

static void put16(guint8 *p, guint16 v)
{
	p[0] = (guint8)(v >> 8);
	p[1] = (guint8)v;
}

static void put32(guint8 *p, guint32 v)
{
	p[0] = (guint8)(v >> 24);
	p[1] = (guint8)(v >> 16);
	p[2] = (guint8)(v >> 8);
	p[3] = (guint8)v;
}

static guint16 get16(const guint8 *p)
{
	return (guint16)((p[0] << 8) | p[1]);
}

static guint32 get32(const guint8 *p)
{
	return ((guint32)p[0] << 24) | ((guint32)p[1] << 16) | ((guint32)p[2] << 8) | (guint32)p[3];
}

void hl_b_init(HlBuilder *b)
{
	b->body = g_byte_array_new();
	b->count = 0;
}

void hl_b_bytes(HlBuilder *b, guint16 id, const void *data, gsize len)
{
	guint8 h[4];
	if (len > 0xFFFF)
		len = 0xFFFF;   /* a field can't be longer; callers check limits first */
	put16(h, id);
	put16(h + 2, (guint16)len);
	g_byte_array_append(b->body, h, 4);
	if (len > 0)
		g_byte_array_append(b->body, (const guint8 *)data, (guint)len);
	b->count++;
}

void hl_b_str(HlBuilder *b, guint16 id, const char *s)
{
	hl_b_bytes(b, id, s ? s : "", s ? strlen(s) : 0);
}

void hl_b_u16(HlBuilder *b, guint16 id, guint16 v)
{
	guint8 d[2];
	put16(d, v);
	hl_b_bytes(b, id, d, 2);
}

void hl_b_int(HlBuilder *b, guint16 id, guint32 v)
{
	guint8 d[4];
	if (v <= 0xFFFF) {
		hl_b_u16(b, id, (guint16)v);
		return;
	}
	put32(d, v);
	hl_b_bytes(b, id, d, 4);
}

GByteArray *hl_b_finish(HlBuilder *b, guint16 type, guint32 id)
{
	GByteArray *out = g_byte_array_new();
	guint8 h[HL_HEADER_LEN + 2];
	guint32 body_len = b->body->len + 2;
	h[0] = 0;   /* flags */
	h[1] = 0;   /* a request */
	put16(h + 2, type);
	put32(h + 4, id);
	put32(h + 8, 0);
	put32(h + 12, body_len);
	put32(h + 16, body_len);
	put16(h + 20, b->count);
	g_byte_array_append(out, h, sizeof h);
	g_byte_array_append(out, b->body->data, b->body->len);
	hl_b_free(b);
	return out;
}

void hl_b_free(HlBuilder *b)
{
	if (b->body)
		g_byte_array_free(b->body, TRUE);
	b->body = NULL;
}

void hl_header_sizes(const guint8 *header, guint32 *total, guint32 *part)
{
	*total = get32(header + 12);
	*part = get32(header + 16);
}

HlTxn *hl_txn_parse(const guint8 *header, const guint8 *payload, gsize len)
{
	HlTxn *t = g_new0(HlTxn, 1);
	guint i, count;
	gsize p = 2;

	t->flags = header[0];
	t->is_reply = header[1] != 0;
	t->type = get16(header + 2);
	t->id = get32(header + 4);
	t->error = get32(header + 8);
	if (len < 2)
		return t;   /* no fields: an empty payload is allowed */
	t->payload = g_malloc(len);
	memcpy(t->payload, payload, len);
	t->payload_len = len;
	count = get16(t->payload);
	t->fields = g_new0(HlField, count ? count : 1);
	for (i = 0; i < count; i++) {
		guint16 fid, flen;
		if (p + 4 > len)
			goto bad;
		fid = get16(t->payload + p);
		flen = get16(t->payload + p + 2);
		p += 4;
		if (p + flen > len)
			goto bad;
		t->fields[i].id = fid;
		t->fields[i].len = flen;
		t->fields[i].data = t->payload + p;
		p += flen;
	}
	t->nfields = count;
	return t;
bad:
	hl_txn_free(t);
	return NULL;
}

void hl_txn_free(HlTxn *t)
{
	if (!t)
		return;
	g_free(t->payload);
	g_free(t->fields);
	g_free(t);
}

const HlField *hl_txn_get(const HlTxn *t, guint16 id)
{
	guint i;
	for (i = 0; i < t->nfields; i++)
		if (t->fields[i].id == id)
			return &t->fields[i];
	return NULL;
}

guint32 hl_field_uint(const HlField *f)
{
	guint32 v = 0;
	guint i;
	if (!f)
		return 0;
	for (i = 0; i < f->len && i < 4; i++)
		v = (v << 8) | f->data[i];
	return v;
}

gboolean hl_txn_uint(const HlTxn *t, guint16 id, guint32 *out)
{
	const HlField *f = hl_txn_get(t, id);
	if (!f)
		return FALSE;
	*out = hl_field_uint(f);
	return TRUE;
}

void hl_b_name_list(HlBuilder *b, guint16 id, const char *const *names, guint n)
{
	GByteArray *d = g_byte_array_new();
	guint8 h[2];
	guint i;
	put16(h, (guint16)n);
	g_byte_array_append(d, h, 2);
	for (i = 0; i < n; i++) {
		guint8 l = (guint8)strlen(names[i]);
		g_byte_array_append(d, &l, 1);
		g_byte_array_append(d, (const guint8 *)names[i], l);
	}
	hl_b_bytes(b, id, d->data, d->len);
	g_byte_array_free(d, TRUE);
}

char *hl_first_name(const HlField *f)
{
	guint l;
	if (!f || f->len < 3 || get16(f->data) == 0)
		return NULL;
	l = f->data[2];
	if (3 + l > f->len)
		return NULL;
	return g_strndup((const char *)f->data + 3, l);
}

char *hl_hex(const guint8 *data, gsize len)
{
	static const char digits[] = "0123456789abcdef";
	char *s = g_malloc(len * 2 + 1);
	gsize i;
	for (i = 0; i < len; i++) {
		s[2 * i] = digits[data[i] >> 4];
		s[2 * i + 1] = digits[data[i] & 15];
	}
	s[len * 2] = 0;
	return s;
}
