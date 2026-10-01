/*
 * purple-hotline for Adium: Adium's usual account window, plus "Get a Screen Name...".
 * Hotline has no sign-up command (servers' owners make accounts), so the button opens
 * VesperNet's messenger sign-up page, as HIM's "Create a Screen Name" does.
 * Copyright (c) 2026 John Leighow. MIT license.
 */
#import "HotlineAccountViewController.h"

#define HL_SIGNUP_URL @"https://agora.vespernet.net/messenger"

@implementation HotlineAccountViewController

- (NSView *)setupView
{
	NSView *view = [super setupView];
	if (view && !addedSignUp) {
		NSArray *subviews = [view subviews];
		NSRect frame = [view frame];
		float lowest = frame.size.height;
		NSButton *button;
		NSTextField *note;
		unsigned i;

		addedSignUp = YES;
		/* Under the lowest of Adium's own controls (screen name, password). */
		for (i = 0; i < [subviews count]; i++) {
			NSRect r = [[subviews objectAtIndex:i] frame];
			if (r.origin.y < lowest)
				lowest = r.origin.y;
		}
		if (lowest < 64) {   /* no room below: make some */
			frame.size.height += 64 - lowest;
			[view setFrame:frame];
			lowest = 64;
		}

		note = [[[NSTextField alloc] initWithFrame:NSMakeRect(17, lowest - 30, frame.size.width - 34, 17)] autorelease];
		[note setStringValue:@"New to Hotline? Get a free screen name on VesperNet, then enter it above."];
		[note setBezeled:NO];
		[note setDrawsBackground:NO];
		[note setEditable:NO];
		[note setSelectable:NO];
		[note setFont:[NSFont systemFontOfSize:[NSFont smallSystemFontSize]]];
		[note setTextColor:[NSColor disabledControlTextColor]];
		[note setAutoresizingMask:NSViewWidthSizable | NSViewMinYMargin];
		[view addSubview:note];

		button = [[[NSButton alloc] initWithFrame:NSMakeRect(14, lowest - 60, 180, 28)] autorelease];
		[button setTitle:[NSString stringWithUTF8String:"Get a Screen Name\xE2\x80\xA6"]];
		[button setBezelStyle:NSRoundedBezelStyle];
		[button setTarget:self];
		[button setAction:@selector(getScreenName:)];
		[button sizeToFit];
		[button setAutoresizingMask:NSViewMinYMargin];
		[view addSubview:button];
	}
	return view;
}

- (IBAction)getScreenName:(id)sender
{
	[[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:HL_SIGNUP_URL]];
}

@end
