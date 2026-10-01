/*
 * A headless libpurple client that loads the plugin and runs real sessions against
 * HIM's mock server (hotline-im's mock-server: alice, bob, carol, dave, HotBot,
 * password "hotline"). Usage: test_client <plugin dir> <port>
 */
#include <glib.h>
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
#include "plugin.h"
#include "prefs.h"
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
			ok(1, "alice sees bob away: \"out to lunch\"");
			send_im(alice, "hotbot", "ping");
			done = TRUE;
		}
		break;
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
		if (authorized && st && strcmp(st, "available") == 0) {
			ok(1, "alice is asked, accepts, and dave sees her available");
			purple_account_set_enabled(bob, purple_core_get_ui(), FALSE);
			done = TRUE;
		}
		break;
	case 7:
		st = status_of(alice, "bob", NULL);
		if (st && strcmp(st, "offline") == 0) {
			ok(1, "bob signs off and alice sees it");
			g_main_loop_quit(loop);
			return FALSE;
		}
		break;
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
	home = g_build_filename(g_get_tmp_dir(), "purple-hotline-test", NULL);
	purple_util_set_user_dir(home);
	purple_debug_set_enabled(getenv("HL_DEBUG") != NULL);
	purple_eventloop_set_ui_ops(&loop_ops);
	purple_accounts_set_ui_ops(&account_ops);
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
