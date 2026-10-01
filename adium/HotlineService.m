/*
 * purple-hotline for Adium: how Adium shows and sets up Hotline accounts.
 * Copyright (c) 2026 John Leighow. MIT license.
 */
#import "HotlineService.h"
#import "HotlineAccount.h"
#import "HotlineAccountViewController.h"
#import <Adium/AIAccountViewController.h>
#import <Adium/AIStatusControllerProtocol.h>
#import <Adium/AISharedAdium.h>
#import <AIUtilities/AIImageAdditions.h>

@implementation HotlineService

- (Class)accountClass
{
	return [HotlineAccount class];
}

- (AIAccountViewController *)accountViewController
{
	return [HotlineAccountViewController accountViewController];
}

- (DCJoinChatViewController *)joinChatView
{
	return nil;
}

- (NSString *)serviceCodeUniqueID { return @"prpl-hotline"; }
- (NSString *)serviceID { return @"Hotline"; }
- (NSString *)serviceClass { return @"Hotline"; }
- (NSString *)shortDescription { return @"Hotline"; }
- (NSString *)longDescription { return @"Hotline (HIM)"; }
- (NSString *)userNameLabel { return @"Screen Name"; }
- (NSString *)UIDPlaceholder { return @"your Hotline login"; }

- (BOOL)supportsProxySettings { return YES; }
- (BOOL)supportsPassword { return YES; }
- (BOOL)requiresPassword { return YES; }
- (BOOL)canCreateGroupChats { return NO; }
- (BOOL)caseSensitive { return NO; }
- (AIServiceImportance)serviceImportance { return AIServiceSecondary; }

- (NSCharacterSet *)allowedCharacters
{
	return [[NSCharacterSet controlCharacterSet] invertedSet];
}

- (NSUInteger)allowedLength
{
	return 64;
}

- (NSImage *)defaultServiceIconOfType:(AIServiceIconType)iconType
{
	NSString *name = (iconType == AIServiceIconSmall || iconType == AIServiceIconList) ? @"hotline16" : @"hotline";
	return [NSImage imageNamed:name forClass:[self class] loadLazily:YES];
}

- (NSString *)pathForDefaultServiceIconOfType:(AIServiceIconType)iconType
{
	NSString *name = (iconType == AIServiceIconSmall || iconType == AIServiceIconList) ? @"hotline16" : @"hotline";
	return [[NSBundle bundleForClass:[self class]] pathForImageResource:name];
}

- (void)registerStatuses
{
	id<AIStatusController> sc = adium.statusController;
	[sc registerStatus:STATUS_NAME_AVAILABLE
	   withDescription:[sc localizedDescriptionForCoreStatusName:STATUS_NAME_AVAILABLE]
	            ofType:AIAvailableStatusType forService:self];
	[sc registerStatus:STATUS_NAME_AWAY
	   withDescription:[sc localizedDescriptionForCoreStatusName:STATUS_NAME_AWAY]
	            ofType:AIAwayStatusType forService:self];
	[sc registerStatus:STATUS_NAME_BUSY
	   withDescription:[sc localizedDescriptionForCoreStatusName:STATUS_NAME_BUSY]
	            ofType:AIAwayStatusType forService:self];
	[sc registerStatus:STATUS_NAME_INVISIBLE
	   withDescription:[sc localizedDescriptionForCoreStatusName:STATUS_NAME_INVISIBLE]
	            ofType:AIInvisibleStatusType forService:self];
	[sc registerStatus:STATUS_NAME_OFFLINE
	   withDescription:[sc localizedDescriptionForCoreStatusName:STATUS_NAME_OFFLINE]
	            ofType:AIOfflineStatusType forService:self];
}

@end
