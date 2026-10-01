/*
 * purple-hotline for Adium: Join Group Chat, as a list of Hotline servers from
 * tracker.bigredh.com. Busy servers show; "Show quiet and hidden servers" adds the
 * ones with no one there and the file mirrors and welcome servers. Any address can
 * be typed in too. Built in code (no nib), in Objective-C that older Adiums take.
 * Copyright (c) 2026 John Leighow. MIT license.
 */
#import "HotlineJoinChatViewController.h"
#import <Adium/AIAccount.h>

#include <glib.h>
#include "hl_room.h"
#include "hl_tracker.h"

@interface NSObject (HotlineJoinChatDelegate)
- (void)setJoinChatEnabled:(BOOL)enabled;
@end

@interface HotlineJoinChatViewController (Private)
- (void)gotServers:(NSArray *)list error:(NSString *)error;
- (void)refilter;
- (void)validate;
@end

static NSString *str(const char *s)
{
	NSString *o = s ? [NSString stringWithUTF8String:s] : nil;
	return o ? o : @"";
}

/* The tracker's answer, handed to the view as plain Cocoa objects. */
static void got_servers(GPtrArray *list, const char *error, gpointer data)
{
	HotlineJoinChatViewController *self = (HotlineJoinChatViewController *)data;
	NSMutableArray *out = nil;
	guint i;
	if (list) {
		out = [NSMutableArray arrayWithCapacity:list->len];
		for (i = 0; i < list->len; i++) {
			HlServer *s = (HlServer *)g_ptr_array_index(list, i);
			char *addr = hl_server_address(s);
			[out addObject:[NSDictionary dictionaryWithObjectsAndKeys:
				str(s->name), @"name",
				str(s->description), @"about",
				str(addr), @"address",
				[NSNumber numberWithInt:s->users], @"users",
				[NSNumber numberWithInt:(int)s->kind], @"kind",
				nil]];
			g_free(addr);
		}
	}
	[self gotServers:out error:(error ? str(error) : nil)];
	[self release];   /* retained while the fetch was out */
}

@implementation HotlineJoinChatViewController

- (NSString *)nibName
{
	return nil;   /* built below */
}

- (id)init
{
	if ((self = [super init])) {
		NSScrollView *scroll;
		NSTableColumn *col;
		NSTextField *label;

		view = [[NSView alloc] initWithFrame:NSMakeRect(0, 0, 440, 280)];

		label = [[[NSTextField alloc] initWithFrame:NSMakeRect(0, 258, 440, 17)] autorelease];
		[label setStringValue:@"Public Hotline servers (from tracker.bigredh.com):"];
		[label setBezeled:NO];
		[label setDrawsBackground:NO];
		[label setEditable:NO];
		[label setSelectable:NO];
		[view addSubview:label];

		scroll = [[[NSScrollView alloc] initWithFrame:NSMakeRect(0, 82, 440, 172)] autorelease];
		[scroll setHasVerticalScroller:YES];
		[scroll setBorderType:NSBezelBorder];
		[scroll setAutoresizingMask:NSViewWidthSizable | NSViewHeightSizable];
		table = [[NSTableView alloc] initWithFrame:[[scroll contentView] bounds]];
		col = [[[NSTableColumn alloc] initWithIdentifier:@"name"] autorelease];
		[[col headerCell] setStringValue:@"Server"];
		[col setWidth:170];
		[table addTableColumn:col];
		col = [[[NSTableColumn alloc] initWithIdentifier:@"users"] autorelease];
		[[col headerCell] setStringValue:@"People"];
		[col setWidth:50];
		[table addTableColumn:col];
		col = [[[NSTableColumn alloc] initWithIdentifier:@"about"] autorelease];
		[[col headerCell] setStringValue:@"About"];
		[col setWidth:200];
		[table addTableColumn:col];
		[table setDataSource:(id)self];
		[table setDelegate:(id)self];
		[table setTarget:self];
		[table setDoubleAction:@selector(doubleClicked:)];
		[table setUsesAlternatingRowBackgroundColors:YES];
		/* Nothing chosen until you click a row: a highlighted first row would quietly fill
		 * in its address, and Join would take you somewhere you didn't pick. */
		[table setAllowsEmptySelection:YES];
		[scroll setDocumentView:table];
		[view addSubview:scroll];

		showAll = [[NSButton alloc] initWithFrame:NSMakeRect(0, 56, 300, 20)];
		[showAll setButtonType:NSSwitchButton];
		[showAll setTitle:@"Show quiet and hidden servers"];
		[showAll setTarget:self];
		[showAll setAction:@selector(toggledShowAll:)];
		[showAll setAutoresizingMask:NSViewMaxYMargin];
		[view addSubview:showAll];

		status = [[NSTextField alloc] initWithFrame:NSMakeRect(300, 56, 140, 17)];
		[status setBezeled:NO];
		[status setDrawsBackground:NO];
		[status setEditable:NO];
		[status setSelectable:NO];
		[status setAlignment:NSRightTextAlignment];
		[status setTextColor:[NSColor disabledControlTextColor]];
		[status setFont:[NSFont systemFontOfSize:[NSFont smallSystemFontSize]]];
		[status setAutoresizingMask:NSViewMinXMargin | NSViewMaxYMargin];
		[view addSubview:status];

		label = [[[NSTextField alloc] initWithFrame:NSMakeRect(0, 28, 120, 17)] autorelease];
		[label setStringValue:@"Server address:"];
		[label setBezeled:NO];
		[label setDrawsBackground:NO];
		[label setEditable:NO];
		[label setSelectable:NO];
		[label setAutoresizingMask:NSViewMaxYMargin];
		[view addSubview:label];

		address = [[NSTextField alloc] initWithFrame:NSMakeRect(120, 26, 320, 22)];
		[[address cell] setPlaceholderString:@"hotline.example.com:5500"];
		[address setDelegate:(id)self];
		[address setAutoresizingMask:NSViewWidthSizable | NSViewMaxYMargin];
		[view addSubview:address];
	}
	return self;
}

- (void)dealloc
{
	[table setDataSource:nil];
	[table setDelegate:nil];
	[table release];
	[showAll release];
	[address release];
	[status release];
	[servers release];
	[shown release];
	[super dealloc];
}

- (void)configureForAccount:(AIAccount *)inAccount
{
	[super configureForAccount:inAccount];
	if (!servers && !loading) {
		loading = YES;
		[status setStringValue:[NSString stringWithUTF8String:"Loading\xE2\x80\xA6"]];
		[self retain];
		hl_tracker_fetch(NULL, got_servers, self);
	}
	[[view window] makeFirstResponder:address];
	[self validate];
}

- (void)gotServers:(NSArray *)list error:(NSString *)error
{
	loading = NO;
	[servers release];
	servers = [list retain];
	[status setStringValue:(list ? @"" : @"Couldn't load the list")];
	if (error)
		NSLog(@"Hotline: %@", error);
	[self refilter];
}

- (void)refilter
{
	NSMutableArray *list = [NSMutableArray array];
	BOOL all = [showAll state] == NSOnState;
	unsigned i;
	for (i = 0; i < [servers count]; i++) {
		NSDictionary *s = [servers objectAtIndex:i];
		if (all || [[s objectForKey:@"kind"] intValue] == HL_SERVER_BUSY)
			[list addObject:s];
	}
	[shown release];
	shown = [list retain];
	[table reloadData];
	[table deselectAll:nil];
}

- (IBAction)toggledShowAll:(id)sender
{
	[self refilter];
}

/* ---- the table ---- */

- (int)numberOfRowsInTableView:(NSTableView *)tv
{
	return (int)[shown count];
}

- (id)tableView:(NSTableView *)tv objectValueForTableColumn:(NSTableColumn *)col row:(int)row
{
	NSDictionary *s = [shown objectAtIndex:row];
	NSString *key = [col identifier];
	if ([key isEqualToString:@"users"]) {
		int n = [[s objectForKey:@"users"] intValue];
		return n < 0 ? @"" : [NSString stringWithFormat:@"%d", n];
	}
	return [s objectForKey:key];
}

/* Quiet and hidden servers are dimmed when shown. */
- (void)tableView:(NSTableView *)tv willDisplayCell:(id)cell forTableColumn:(NSTableColumn *)col row:(int)row
{
	BOOL busy = [[[shown objectAtIndex:row] objectForKey:@"kind"] intValue] == HL_SERVER_BUSY;
	if ([cell respondsToSelector:@selector(setTextColor:)])
		[cell setTextColor:(busy ? [NSColor controlTextColor] : [NSColor disabledControlTextColor])];
}

/* A row you click fills in its address (only a click: reloading the list doesn't). */
- (void)tableViewSelectionDidChange:(NSNotification *)n
{
	int row = [table selectedRow];
	NSEvent *e = [NSApp currentEvent];
	BOOL clicked = e && ([e type] == NSLeftMouseDown || [e type] == NSLeftMouseUp || [e type] == NSKeyDown);
	if (clicked && row >= 0 && row < (int)[shown count])
		[address setStringValue:[[shown objectAtIndex:row] objectForKey:@"address"]];
	[self validate];
}

- (IBAction)doubleClicked:(id)sender
{
	if ([table clickedRow] >= 0 && account)
		[self joinChatWithAccount:account];
}

/* ---- joining ---- */

- (void)controlTextDidChange:(NSNotification *)n
{
	[self validate];
}

- (void)validate
{
	if (delegate && [delegate respondsToSelector:@selector(setJoinChatEnabled:)])
		[delegate setJoinChatEnabled:([[address stringValue] length] > 0)];
}

- (void)joinChatWithAccount:(AIAccount *)inAccount
{
	NSString *where = [[address stringValue] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
	NSString *title = where;
	NSMutableDictionary *info;
	char *host = NULL;
	int port = 5500;
	unsigned i;

	if (![where length] || !hl_parse_address([where UTF8String], &host, &port))
		return;
	/* The chat's name is the address as the plugin writes it (no ":5500"). */
	where = port == 5500 ? str(host) : [NSString stringWithFormat:@"%@:%d", str(host), port];
	g_free(host);
	for (i = 0; i < [servers count]; i++) {
		NSDictionary *s = [servers objectAtIndex:i];
		if ([[s objectForKey:@"address"] isEqualToString:where])
			title = [s objectForKey:@"name"];
	}
	info = [NSMutableDictionary dictionaryWithObject:where forKey:@"server"];
	[info setObject:title forKey:@"name"];
	[self doJoinChatWithName:where
	               onAccount:inAccount
	        chatCreationInfo:info
	        invitingContacts:nil
	   withInvitationMessage:nil];
}

@end
