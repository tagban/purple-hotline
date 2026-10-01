/*
 * purple-hotline for Adium: registers the libpurple protocol and Adium's service
 * for it. Copyright (c) 2026 John Leighow. MIT license.
 */
#import "HotlinePlugin.h"
#import "HotlineService.h"

#include <glib.h>

extern gboolean purple_init_hotline_plugin(void);

@implementation HotlinePlugin

/* The service is Adium's, so it's registered as soon as the bundle loads. The protocol
 * is libpurple's: Adium 1.5 takes it right away (as other plugins do), but Adium 1.3
 * loads bundles before libpurple starts, so there it waits (build-tiger.sh sets
 * HL_ADIUM_13). */
- (void)installPlugin
{
#ifndef HL_ADIUM_13
	purple_init_hotline_plugin();
#endif
	[HotlineService registerService];
}

- (void)installLibpurplePlugin
{
#ifdef HL_ADIUM_13
	purple_init_hotline_plugin();
#endif
}

- (void)loadLibpurplePlugin
{
}

- (void)uninstallPlugin
{
}

- (NSString *)pluginAuthor
{
	return @"John Leighow";
}

- (NSString *)pluginVersion
{
	return [[[NSBundle bundleForClass:[self class]] infoDictionary] objectForKey:@"CFBundleShortVersionString"];
}

- (NSString *)pluginDescription
{
	return @"Hotline Instant Messaging (HIM), with HOPE secure sign-in";
}

- (NSString *)pluginURL
{
	return @"https://github.com/tagban/purple-hotline";
}

@end
