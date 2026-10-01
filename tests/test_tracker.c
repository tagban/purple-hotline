/* The tracker's lists, from a saved copy of tracker.bigredh.com's files. */
#include "../src/hl_tracker.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void ok(int pass, const char *what)
{
	printf("%s %s\n", pass ? "ok  " : "FAIL", what);
	if (!pass)
		failures++;
}

static HlServer *find(GPtrArray *l, const char *host, int port)
{
	guint i;
	for (i = 0; i < l->len; i++) {
		HlServer *s = g_ptr_array_index(l, i);
		if (strcmp(s->host, host) == 0 && s->port == port)
			return s;
	}
	return NULL;
}

int main(int argc, char **argv)
{
	gchar *servers, *live;
	gsize sl, ll;
	GPtrArray *list;
	HlServer *s;
	guint i, busy = 0, quiet = 0, hidden = 0;
	int sorted = 1;

	if (!g_file_get_contents(argv[1], &servers, &sl, NULL) || !g_file_get_contents(argv[2], &live, &ll, NULL)) {
		printf("FAIL reading the fixtures\n");
		return 1;
	}
	list = hl_tracker_parse(servers, sl, live, ll);
	ok(list && list->len > 50, "the server list parses");
	if (!list)
		return 1;
	for (i = 0; i < list->len; i++) {
		HlServer *x = g_ptr_array_index(list, i);
		if (x->kind == HL_SERVER_BUSY) busy++;
		else if (x->kind == HL_SERVER_QUIET) quiet++;
		else hidden++;
		if (i > 0) {
			HlServer *p = g_ptr_array_index(list, i - 1);
			if (p->kind > x->kind || (p->kind == x->kind && p->users < x->users))
				sorted = 0;
		}
	}
	printf("     %u busy, %u quiet, %u hidden\n", busy, quiet, hidden);
	s = find(list, "62.116.228.143", 5500);
	ok(s && strcmp(s->name, "MacDomain") == 0 && s->users == 8 && s->kind == HL_SERVER_BUSY,
	   "MacDomain is listed busy, with 8 people");
	s = find(list, "50.65.99.228", 9999);
	ok(s && s->kind == HL_SERVER_HIDDEN, "MAJOR MAC BACKUP - GOLD is hidden (though people are there)");
	s = find(list, "104.200.25.101", 5500);
	ok(s && s->kind == HL_SERVER_QUIET, "a server with no one there is quiet");
	ok(sorted, "busy first, then quiet, then hidden; most people first");
	ok(hl_server_name_is_junk("Welcome to Hotline!") && hl_server_name_is_junk("--Welcome--") &&
	   hl_server_name_is_junk("------------") && hl_server_name_is_junk("major mac backup") &&
	   !hl_server_name_is_junk("MacDomain") && !hl_server_name_is_junk("Welcome home"),
	   "junk names: welcome servers, backups and dividers (not every 'welcome')");
	hl_servers_free(list);
	list = hl_tracker_parse(servers, sl, NULL, 0);
	ok(list && list->len > 50, "without live.json the list still loads");
	hl_servers_free(list);
	ok(hl_tracker_parse("not json", 8, NULL, 0) == NULL, "something that isn't JSON is refused");
	printf(failures ? "%d failed\n" : "all good\n", failures);
	return failures != 0;
}
