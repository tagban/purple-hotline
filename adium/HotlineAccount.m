/*
 * purple-hotline for Adium: a Hotline account, run by the libpurple protocol.
 * Copyright (c) 2026 John Leighow. MIT license.
 */
#import "HotlineAccount.h"
#import <Adium/AIStatus.h>
#import <Adium/AIStatusControllerProtocol.h>

@implementation HotlineAccount

- (const char *)protocolPlugin
{
	return "prpl-hotline";
}

- (NSString *)connectionStringForStep:(NSInteger)step
{
	switch (step) {
	case 1: return @"Connecting";
	case 2: return @"Signing in";
	}
	return nil;
}

/* Busy is its own state on Hotline, not just another away. */
- (const char *)purpleStatusIDForStatus:(AIStatus *)statusState arguments:(NSMutableDictionary *)arguments
{
	if ([statusState.statusName isEqualToString:STATUS_NAME_BUSY])
		return "busy";
	return [super purpleStatusIDForStatus:statusState arguments:arguments];
}

- (NSString *)statusNameForPurpleBuddy:(PurpleBuddy *)buddy
{
	PurplePresence *presence = purple_buddy_get_presence(buddy);
	PurpleStatus *status = presence ? purple_presence_get_active_status(presence) : NULL;
	const char *sid = status ? purple_status_get_id(status) : NULL;
	if (sid && strcmp(sid, "busy") == 0)
		return STATUS_NAME_BUSY;
	return [super statusNameForPurpleBuddy:buddy];
}

/* Hotline keeps messages for buddies who are away: let Adium send to them. */
- (BOOL)canSendOfflineMessageToContact:(AIListContact *)inContact
{
	return YES;
}

@end
