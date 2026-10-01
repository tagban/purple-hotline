/* purple-hotline for Adium: Join Group Chat, as a list of Hotline servers. MIT license. */
#import <Adium/DCJoinChatViewController.h>

@class NSTableView, NSButton, NSTextField;

@interface HotlineJoinChatViewController : DCJoinChatViewController {
	NSTableView *table;
	NSButton *showAll;
	NSTextField *address;
	NSTextField *status;
	NSArray *servers;     /* every server the tracker lists (dictionaries) */
	NSArray *shown;       /* the ones on screen */
	BOOL loading;
}
@end
