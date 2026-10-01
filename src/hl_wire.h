/*
 * purple-hotline: Hotline transactions (fogWraith's Client-Creation-Guide §5).
 * A 20-byte header, then a field list; every integer is big-endian.
 *
 * Copyright (c) 2026 John Leighow. MIT license (see LICENSE).
 */
#ifndef HL_WIRE_H
#define HL_WIRE_H

#include <glib.h>

#define HL_HEADER_LEN 20
#define HL_MAX_TXN (16 * 1024 * 1024)

/* Transactions */
enum {
	HL_TX_LOGIN = 107,
	HL_TX_SHOW_AGREEMENT = 109,
	HL_TX_DISCONNECT_MSG = 111,
	HL_TX_SERVER_MSG = 104,
	HL_TX_AGREED = 121,
	HL_TX_GET_ROSTER = 800,
	HL_TX_ROSTER_ENTRY = 801,
	HL_TX_ADD_FRIEND = 802,
	HL_TX_REMOVE_FRIEND = 803,
	HL_TX_FRIEND_REQUEST = 804,
	HL_TX_FRIEND_RESPONSE = 805,
	HL_TX_BLOCK_USER = 806,
	HL_TX_UNBLOCK_USER = 807,
	HL_TX_SET_PRESENCE = 808,
	HL_TX_PRESENCE_CHANGED = 809,
	HL_TX_IM_SEND = 810,
	HL_TX_IM_DELIVER = 811,
	HL_TX_IM_ACK = 812,
	HL_TX_IM_TYPING = 813,
	HL_TX_FIND_USER = 822,
	HL_TX_USER_SEARCH = 823,
	HL_TX_SET_FRIEND_NICKNAME = 824,
	HL_TX_GET_USER_INFO = 825,
	HL_TX_SET_USER_INFO = 826,
	HL_TX_SET_BUDDY_ICON = 827,
	HL_TX_GET_BUDDY_ICON = 828
};

/* Fields */
enum {
	HL_F_ERROR = 100,
	HL_F_DATA = 101,
	HL_F_USER_NAME = 102,
	HL_F_USER_ID = 103,
	HL_F_USER_ICON_ID = 104,
	HL_F_USER_LOGIN = 105,
	HL_F_USER_PASSWORD = 106,
	HL_F_OPTIONS = 113,
	HL_F_NO_AGREEMENT = 154,
	HL_F_VERSION = 160,
	HL_F_SERVER_NAME = 162,
	HL_F_CAPABILITIES = 0x01F0,

	HL_F_HOPE_APP_ID = 0x0E01,
	HL_F_HOPE_APP_STRING = 0x0E02,
	HL_F_HOPE_SESSION_KEY = 0x0E03,
	HL_F_HOPE_MAC_ALGORITHM = 0x0E04,
	HL_F_HOPE_SERVER_CIPHER = 0x0EC1,
	HL_F_HOPE_CLIENT_CIPHER = 0x0EC2,

	HL_F_FRIEND_LOGIN = 0x0600,
	HL_F_FRIEND_NICKNAME = 0x0601,
	HL_F_PRESENCE_STATE = 0x0602,
	HL_F_PRESENCE_STATUS_TEXT = 0x0603,
	HL_F_ROSTER_STATE = 0x0604,
	HL_F_MESSAGE_GUID = 0x0605,
	HL_F_MESSAGE_BODY = 0x0606,
	HL_F_MESSAGE_TIMESTAMP = 0x0607,
	HL_F_ACK_TYPE = 0x0608,
	HL_F_TYPING_STATE = 0x0609,
	HL_F_REASON_CODE = 0x060F,
	HL_F_REQUEST_NOTE = 0x0610,
	HL_F_SEARCH_QUERY = 0x0612,
	HL_F_FRIEND_CAPABILITIES = 0x0613,
	HL_F_PROFILE_NICKNAME = 0x0614,
	HL_F_PROFILE_FIRST_NAME = 0x0615,
	HL_F_PROFILE_LAST_NAME = 0x0616,
	HL_F_PROFILE_EMAIL = 0x0617,
	HL_F_PROFILE_COUNTRY = 0x061A,
	HL_F_BUDDY_ICON = 0x061D,
	HL_F_BUDDY_ICON_HASH = 0x061E,
	HL_F_MAX_MESSAGE_BYTES = 0x0620,
	HL_F_MAX_ICON_BYTES = 0x0623
};

/* DATA_CAPABILITIES bits */
#define HL_CAP_TEXT_ENCODING (1 << 1)
#define HL_CAP_MESSAGING (1 << 6)
#define HL_CAP_MESSENGER_SESSION (1 << 8)

/* DATA_REASON_CODE values worth naming */
#define HL_REASON_OK 0
#define HL_REASON_NOT_FRIENDS 6
#define HL_REASON_OFFLINE_QUEUED 7

typedef struct {
	guint16 id;
	guint16 len;
	const guint8 *data;   /* points into the transaction's payload */
} HlField;

typedef struct {
	guint8 flags;
	gboolean is_reply;
	guint16 type;
	guint32 id;
	guint32 error;
	guint8 *payload;
	gsize payload_len;
	HlField *fields;
	guint nfields;
} HlTxn;

/* Building a request: add fields, then encode it with a type and task ID. */
typedef struct {
	GByteArray *body;
	guint16 count;
} HlBuilder;

void hl_b_init(HlBuilder *b);
void hl_b_bytes(HlBuilder *b, guint16 id, const void *data, gsize len);
void hl_b_str(HlBuilder *b, guint16 id, const char *s);
void hl_b_u16(HlBuilder *b, guint16 id, guint16 v);
/* Legacy integer fields take the smallest width that fits: 2 bytes, else 4. */
void hl_b_int(HlBuilder *b, guint16 id, guint32 v);
/* The whole transaction (header and fields); frees the builder's buffer. */
GByteArray *hl_b_finish(HlBuilder *b, guint16 type, guint32 id);
void hl_b_free(HlBuilder *b);

/* Sizes from a header: the transaction's total payload and this part's. */
void hl_header_sizes(const guint8 *header, guint32 *total, guint32 *part);
/* Parses a header and its complete payload (copied); NULL if malformed. */
HlTxn *hl_txn_parse(const guint8 *header, const guint8 *payload, gsize len);
void hl_txn_free(HlTxn *t);

const HlField *hl_txn_get(const HlTxn *t, guint16 id);
/* The field as a big-endian integer over its whole size (0 when absent). */
guint32 hl_field_uint(const HlField *f);
gboolean hl_txn_uint(const HlTxn *t, guint16 id, guint32 *out);

/* HOPE's algorithm lists: u16 count, then (u8 length, name) each. */
void hl_b_name_list(HlBuilder *b, guint16 id, const char *const *names, guint n);
/* The first name in such a list, or NULL. Free with g_free. */
char *hl_first_name(const HlField *f);

char *hl_hex(const guint8 *data, gsize len);

#endif
