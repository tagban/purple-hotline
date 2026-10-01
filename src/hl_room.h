/*
 * purple-hotline: chat rooms. A room is a Hotline server's public chat, joined on a
 * connection of its own as a guest (as HIM does), separate from the messenger.
 *
 * Copyright (c) 2026 John Leighow. MIT license (see LICENSE).
 */
#ifndef HL_ROOM_H
#define HL_ROOM_H

#include "connection.h"

typedef struct _HlRoom HlRoom;

/* Joins `host`:`port` as chat `id` of `gc`, going by `nick` there. */
HlRoom *hl_room_join(PurpleConnection *gc, int id, const char *host, int port, const char *nick);
/* Says something (plain text; "/me waves" is an action). */
void hl_room_send(HlRoom *room, const char *text);
/* Leaves and frees the room. */
void hl_room_leave(HlRoom *room);

/* "host" or "host:port" into its parts (5500 when there's no port). FALSE if it's empty. */
gboolean hl_parse_address(const char *address, char **host, int *port);

#endif
