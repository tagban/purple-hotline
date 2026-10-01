/*
 * A headless libpurple client that loads the plugin and runs real sessions against
 * HIM's mock server (hotline-im's mock-server: alice, bob, carol, dave, HotBot,
 * password "hotline"). Usage: test_client <plugin dir> <port>
 */
#include <glib.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "account.h"
#include "blist.h"
#include "connection.h"
#include "conversation.h"
#include "core.h"
#include "debug.h"
#include "eventloop.h"
#include "notify.h"
#include "plugin.h"
#include "prefs.h"
#include "request.h"
#include "roomlist.h"
#include "server.h"
#include "status.h"
#include "util.h"

static GMainLoop *loop;
static int port;
static int failures;
static int step;
static PurpleAccount *alice, *bob, *dave;

/* what we've seen */
static char *bob_got, *alice_from_hotbot;
static int authorized;
static int errors_shown;
static int suggested_to_dave;
static int found_dave;
static const char *search_for = "da";
static char *dave_heard, *alice_heard;
static int tracker_port;
static PurpleRoomlist *rlist;
static int rooms_top, categories, rooms_in_category;
static PurpleRoomlistRoom *hidden_cat;
static int readd_ticks;

static void ok(int pass, const char *what)
{
	printf("%s %s\n", pass ? "ok  " : "FAIL", what);
	fflush(stdout);
	if (!pass)
		failures++;
}

/* ---- the glib event loop, as libpurple's nullclient does it ---- */

typedef struct {
	PurpleInputFunction function;
	guint result;
	gpointer data;
} IoClosure;

static gboolean io_invoke(GIOChannel *source, GIOCondition condition, gpointer data)
{
	IoClosure *c = data;
	int cond = 0;
	if (condition & (G_IO_IN | G_IO_HUP | G_IO_ERR))
		cond |= PURPLE_INPUT_READ;
	if (condition & (G_IO_OUT | G_IO_HUP | G_IO_ERR | G_IO_NVAL))
		cond |= PURPLE_INPUT_WRITE;
	c->function(c->data, g_io_channel_unix_get_fd(source), cond);
	return TRUE;
}

static guint input_add(gint fd, PurpleInputCondition condition, PurpleInputFunction function, gpointer data)
{
	IoClosure *c = g_new0(IoClosure, 1);
	GIOChannel *ch;
	int cond = 0;
	c->function = function;
	c->data = data;
	if (condition & PURPLE_INPUT_READ)
		cond |= G_IO_IN | G_IO_HUP | G_IO_ERR;
	if (condition & PURPLE_INPUT_WRITE)
		cond |= G_IO_OUT | G_IO_HUP | G_IO_ERR | G_IO_NVAL;
	ch = g_io_channel_unix_new(fd);
	c->result = g_io_add_watch_full(ch, G_PRIORITY_DEFAULT, cond, io_invoke, c, g_free);
	g_io_channel_unref(ch);
	return c->result;
}

static PurpleEventLoopUiOps loop_ops = {
	g_timeout_add, g_source_remove, input_add, g_source_remove, NULL,
	g_timeout_add_seconds, NULL, NULL, NULL
};

/* ---- buddy requests: accept them (and remember we were asked) ---- */

static void *request_authorize(PurpleAccount *account, const char *remote_user, const char *id,
                               const char *alias, const char *message, gboolean on_list,
                               PurpleAccountRequestAuthorizationCb authorize_cb,
                               PurpleAccountRequestAuthorizationCb deny_cb, void *user_data)
{
	if (account == alice && strcmp(remote_user, "dave") == 0) {
		authorized = 1;
		authorize_cb(user_data);
	} else {
		deny_cb(user_data);
	}
	return NULL;
}

static PurpleAccountUiOps account_ops = {
	.request_authorize = request_authorize
};

/* ---- error dialogs: count them ---- */

static void *notify_message(PurpleNotifyMsgType type, const char *title, const char *primary,
                            const char *secondary)
{
	printf("     dialog: %s %s\n", primary ? primary : "", secondary ? secondary : "");
	if (type == PURPLE_NOTIFY_MSG_ERROR)
		errors_shown++;
	return NULL;
}

static void *notify_searchresults(PurpleConnection *gc, const char *title, const char *primary,
                                  const char *secondary, PurpleNotifySearchResults *results, gpointer data)
{
	GList *r;
	for (r = results->rows; r; r = r->next) {
		GList *cols = (GList *)r->data;
		printf("     found: %s (%s)\n", (char *)cols->data, cols->next ? (char *)cols->next->data : "");
		if (strcmp((char *)cols->data, "dave") == 0)
			found_dave = 1;
	}
	return NULL;
}

static PurpleNotifyUiOps notify_ops = {
	.notify_message = notify_message,
	.notify_searchresults = notify_searchresults
};

/* ---- requests: say yes to suggested buddies; type the search ---- */

static void *request_fields(const char *title, const char *primary, const char *secondary,
                            PurpleRequestFields *fields, const char *ok_text, GCallback ok_cb,
                            const char *cancel_text, GCallback cancel_cb, PurpleAccount *account,
                            const char *who, PurpleConversation *conv, void *user_data)
{
	printf("     asked %s: %s\n", purple_account_get_username(account), primary);
	if (account == dave && purple_request_fields_get_field(fields, "carol"))
		suggested_to_dave = 1;
	((PurpleRequestFieldsCb)ok_cb)(user_data, fields);
	return NULL;
}

static void *request_input(const char *title, const char *primary, const char *secondary,
                           const char *default_value, gboolean multiline, gboolean masked, gchar *hint,
                           const char *ok_text, GCallback ok_cb, const char *cancel_text, GCallback cancel_cb,
                           PurpleAccount *account, const char *who, PurpleConversation *conv, void *user_data)
{
	((PurpleRequestInputCb)ok_cb)(user_data, search_for);
	return NULL;
}

static void *request_action(const char *title, const char *primary, const char *secondary, int default_action,
                            PurpleAccount *account, const char *who, PurpleConversation *conv, void *user_data,
                            size_t action_count, va_list actions)
{
	const char *label = va_arg(actions, const char *);
	GCallback cb = va_arg(actions, GCallback);
	printf("     asked %s: %s [%s]\n", purple_account_get_username(account), primary, label);
	if (account == dave && secondary && strstr(secondary, "Carol") && strstr(secondary, "Find a Buddy"))
		suggested_to_dave = 1;
	((PurpleRequestActionCb)cb)(user_data, 0);   /* the first button: Add */
	return NULL;
}

static PurpleRequestUiOps request_ops = {
	.request_input = request_input,
	.request_fields = request_fields,
	.request_action = request_action
};

/* ---- the room list: count what's added ---- */

static void rl_add(PurpleRoomlist *list, PurpleRoomlistRoom *room)
{
	if (room->type == PURPLE_ROOMLIST_ROOMTYPE_CATEGORY) {
		categories++;
		if (strstr(room->name, "Hidden"))
			hidden_cat = room;
	} else if (room->parent) {
		rooms_in_category++;
	} else {
		rooms_top++;
	}
}

static PurpleRoomlistUiOps roomlist_ops = {
	.add_room = rl_add
};

/* ---- signals ---- */

static void received_im(PurpleAccount *account, char *sender, char *message, PurpleConversation *conv,
                        PurpleMessageFlags flags)
{
	char *plain = purple_markup_strip_html(message);
	printf("     %s got from %s: %s\n", purple_account_get_username(account), sender, plain);
	if (account == bob && strcmp(sender, "alice") == 0) {
		g_free(bob_got);
		bob_got = g_strdup(plain);
	}
	if (account == alice && strcmp(sender, "hotbot") == 0) {
		g_free(alice_from_hotbot);
		alice_from_hotbot = g_strdup(plain);
	}
	g_free(plain);
}

static void received_chat(PurpleAccount *account, char *sender, char *message, PurpleConversation *conv,
                          PurpleMessageFlags flags)
{
	char *plain = purple_markup_strip_html(message);
	printf("     %s heard %s in %s: %s\n", purple_account_get_username(account), sender,
	       purple_conversation_get_name(conv), plain);
	if (account == dave && strcmp(sender, "alice") == 0) {
		g_free(dave_heard);
		dave_heard = g_strdup(plain);
	}
	if (account == alice && strcmp(sender, "dave") == 0) {
		g_free(alice_heard);
		alice_heard = g_strdup(plain);
	}
	g_free(plain);
}

static PurpleConvChat *room_of(PurpleAccount *a)
{
	char *name = g_strdup_printf("127.0.0.1:%d", port);
	PurpleConversation *c = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT, name, a);
	g_free(name);
	return c ? PURPLE_CONV_CHAT(c) : NULL;
}

static void join_room(PurpleAccount *a)
{
	GHashTable *h = g_hash_table_new(g_str_hash, g_str_equal);
	char *server = g_strdup_printf("127.0.0.1:%d", port);
	g_hash_table_insert(h, "server", server);
	serv_join_chat(purple_account_get_connection(a), h);
	g_hash_table_destroy(h);
	g_free(server);
}

static void connection_error(PurpleConnection *gc, PurpleConnectionError err, const gchar *desc)
{
	printf("     %s: connection error: %s\n", purple_account_get_username(purple_connection_get_account(gc)), desc);
}

/* ---- helpers ---- */

static PurpleAccount *account(const char *login, const char *password)
{
	PurpleAccount *a = purple_account_new(login, "prpl-hotline");
	purple_account_set_password(a, password);
	purple_account_set_string(a, "server", "127.0.0.1");
	purple_account_set_int(a, "port", port);
	purple_accounts_add(a);
	purple_account_set_enabled(a, purple_core_get_ui(), TRUE);
	return a;
}

static gboolean online(PurpleAccount *a)
{
	return purple_account_is_connected(a);
}

static const char *status_of(PurpleAccount *a, const char *who, const char **msg)
{
	PurpleBuddy *b = purple_find_buddy(a, who);
	PurpleStatus *s;
	if (!b)
		return NULL;
	s = purple_presence_get_active_status(purple_buddy_get_presence(b));
	if (msg)
		*msg = purple_status_get_attr_string(s, "message");
	return purple_status_get_id(s);
}

static void send_im(PurpleAccount *from, const char *to, const char *text)
{
	PurpleConversation *c = purple_conversation_new(PURPLE_CONV_TYPE_IM, from, to);
	purple_conv_im_send(PURPLE_CONV_IM(c), text);
}

/* ---- the script: each step waits for its condition, up to a deadline ---- */

static int waited;

static gboolean tick(gpointer data)
{
	const char *msg = NULL;
	const char *st;
	gboolean done = FALSE;

	if (++waited > 100) {   /* 10 s for any one step */
		ok(0, "the step finished in time");
		g_main_loop_quit(loop);
		return FALSE;
	}
	switch (step) {
	case 0:
		if (online(alice) && online(bob)) {
			ok(1, "alice and bob sign on (HOPE)");
			done = TRUE;
		}
		break;
	case 1:
		st = status_of(alice, "bob", NULL);
		if (st && purple_find_buddy(alice, "carol") && purple_find_buddy(alice, "hotbot") &&
		    strcmp(st, "available") == 0) {
			ok(1, "alice's Buddy List has bob, carol and hotbot, and bob is available");
			send_im(alice, "bob", "hello from <b>purple</b> & co");
			done = TRUE;
		}
		break;
	case 2:
		if (bob_got) {
			ok(strcmp(bob_got, "hello from purple & co") == 0, "bob gets alice's IM, as plain text");
			purple_account_set_status(bob, "away", TRUE, "message", "out to lunch", NULL);
			done = TRUE;
		}
		break;
	case 3:
		st = status_of(alice, "bob", &msg);
		if (st && strcmp(st, "away") == 0 && msg && strcmp(msg, "out to lunch") == 0) {
			PurpleBuddy *again = purple_buddy_new(alice, "bob", NULL);
			ok(1, "alice sees bob away: \"out to lunch\"");
			/* adding someone who's already a buddy (as Adium lets you) */
			purple_blist_add_buddy(again, NULL, purple_group_new("Contacts"), NULL);
			purple_account_add_buddy(alice, again);
			done = TRUE;
		}
		break;
	case 30:
		if (++readd_ticks >= 15) {
			st = status_of(alice, "bob", &msg);
			GSList *bobs = purple_find_buddies(alice, "bob");
			ok(errors_shown == 0 && st && strcmp(st, "away") == 0,
			   "adding bob again shows no error and keeps him away (not offline)");
			ok(g_slist_length(bobs) == 1 &&
			   strcmp(purple_group_get_name(purple_buddy_get_group(bobs->data)), "Contacts") == 0,
			   "and bob is listed once, in the group alice picked");
			g_slist_free(bobs);
			send_im(alice, "hotbot", "ping");
			step = 4;
			waited = 0;
		}
		return TRUE;
	case 4:
		if (alice_from_hotbot) {
			ok(strstr(alice_from_hotbot, "ping") != NULL, "HotBot answers alice");
			dave = account("dave", "hotline");
			done = TRUE;
		}
		break;
	case 5:
		if (online(dave)) {
			PurpleBuddy *b = purple_buddy_new(dave, "alice", NULL);
			PurpleGroup *g = purple_group_new("Buddies");
			purple_blist_add_buddy(b, NULL, g, NULL);
			purple_account_add_buddy(dave, b);
			ok(1, "dave signs on and asks alice to be buddies");
			done = TRUE;
		}
		break;
	case 6:
		st = status_of(dave, "alice", NULL);
		if (authorized && st && strcmp(st, "available") == 0 && purple_find_buddy(dave, "carol")) {
			PurplePlugin *prpl = purple_find_prpl("prpl-hotline");
			PurpleConnection *gc = purple_account_get_connection(alice);
			GList *acts = PURPLE_PLUGIN_ACTIONS(prpl, gc), *l;
			ok(1, "alice is asked, accepts, and dave sees her available");
			ok(suggested_to_dave, "dave is offered a suggested buddy (carol), with where Find a Buddy and chat rooms are, and adds her");
			for (l = acts; l; l = l->next) {
				PurplePluginAction *a = (PurplePluginAction *)l->data;
				if (a && g_str_has_prefix(a->label, "Find")) {
					a->plugin = prpl;
					a->context = gc;
					a->callback(a);   /* Find a Buddy: "da" */
				}
			}
			purple_account_set_enabled(bob, purple_core_get_ui(), FALSE);
			done = TRUE;
		}
		break;
	case 7:
		st = status_of(alice, "bob", NULL);
		if (st && strcmp(st, "offline") == 0 && found_dave) {
			ok(1, "Find a Buddy: alice searches \"da\" and finds dave");
			ok(1, "bob signs off and alice sees it");
			join_room(alice);
			join_room(dave);
			done = TRUE;
		}
		break;
	case 8: {
		PurpleConvChat *ra = room_of(alice), *rd = room_of(dave);
		if (ra && rd && purple_conv_chat_find_user(ra, "dave") && purple_conv_chat_find_user(rd, "alice")) {
			ok(1, "alice and dave join the server's chat and see each other there");
			purple_conv_chat_send(ra, "hello <i>room</i>");
			done = TRUE;
		}
		break;
	}
	case 9:
		if (dave_heard) {
			ok(strcmp(dave_heard, "hello room") == 0, "dave hears alice in the room");
			purple_conv_chat_send(room_of(dave), "/me waves");
			done = TRUE;
		}
		break;
	case 10:
		if (alice_heard) {
			ok(strstr(alice_heard, "waves") != NULL, "alice sees dave's /me action");
			if (tracker_port) {
				char *url = g_strdup_printf("http://127.0.0.1:%d/", tracker_port);
				purple_account_set_string(alice, "tracker_url", url);
				g_free(url);
				rlist = purple_roomlist_get_list(purple_account_get_connection(alice));
			}
			done = TRUE;
		}
		break;
	case 11:
		if (!tracker_port) {
			g_main_loop_quit(loop);
			return FALSE;
		}
		if (rlist && !purple_roomlist_get_in_progress(rlist) && (rooms_top || categories)) {
			printf("     room list: %d busy servers, %d sections\n", rooms_top, categories);
			ok(rooms_top == 15 && categories == 2, "the Room List shows busy servers, with quiet and hidden in sections");
			if (hidden_cat)
				purple_roomlist_expand_category(rlist, hidden_cat);
			done = TRUE;
		}
		break;
	case 12:
		if (rooms_in_category > 0) {
			ok(rooms_in_category == 4, "opening Hidden shows the 4 MAJOR MAC BACKUP servers");
			g_main_loop_quit(loop);
			return FALSE;
		}
		break;
	}
	if (done && step == 3) {
		step = 30;
		waited = 0;
		return TRUE;
	}
	if (done) {
		step++;
		waited = 0;
	}
	return TRUE;
}

int main(int argc, char **argv)
{
	char *home;
	static int handle;

	if (argc < 3) {
		fprintf(stderr, "usage: test_client <plugin dir> <port>\n");
		return 2;
	}
	port = atoi(argv[2]);
	tracker_port = argc > 3 ? atoi(argv[3]) : 0;
	home = g_build_filename(g_get_tmp_dir(), "purple-hotline-test", NULL);
	purple_util_set_user_dir(home);
	purple_debug_set_enabled(getenv("HL_DEBUG") != NULL);
	purple_eventloop_set_ui_ops(&loop_ops);
	purple_accounts_set_ui_ops(&account_ops);
	purple_notify_set_ui_ops(&notify_ops);
	purple_roomlist_set_ui_ops(&roomlist_ops);
	purple_request_set_ui_ops(&request_ops);
	g_setenv("HOTLINE_TEST_SUGGEST", "carol:Carol", TRUE);
	purple_plugins_add_search_path(argv[1]);
	if (!purple_core_init("hotline-test")) {
		fprintf(stderr, "libpurple didn't start\n");
		return 1;
	}
	purple_set_blist(purple_blist_new());
	purple_prefs_set_bool("/purple/away/away_when_idle", FALSE);
	ok(purple_find_prpl("prpl-hotline") != NULL, "the plugin loads");
	if (!purple_find_prpl("prpl-hotline"))
		return 1;

	purple_signal_connect(purple_conversations_get_handle(), "received-im-msg", &handle,
	                      PURPLE_CALLBACK(received_im), NULL);
	purple_signal_connect(purple_conversations_get_handle(), "received-chat-msg", &handle,
	                      PURPLE_CALLBACK(received_chat), NULL);
	purple_signal_connect(purple_connections_get_handle(), "connection-error", &handle,
	                      PURPLE_CALLBACK(connection_error), NULL);

	alice = account("alice", "hotline");
	bob = account("bob", "hotline");
	g_timeout_add(100, tick, NULL);
	loop = g_main_loop_new(NULL, FALSE);
	g_main_loop_run(loop);

	printf(failures ? "%d failed\n" : "all good\n", failures);
	return failures != 0;
}
