/*
 * purple-hotline for Adium: registers the libpurple protocol and Adium's service
 * for it. Copyright (c) 2026 John Leighow. MIT license.
 */
#import "HotlinePlugin.h"
#import "HotlineService.h"

#include <glib.h>

extern gboolean purple_init_hotline_plugin(void);

@implementation HotlinePlugin

/* The service is Adium's, so it's registered as soon as the bundle loads; the protocol
 * is libpurple's, so it waits for libpurple to start (Adium 1.3 loads bundles first). */
- (void)installPlugin
{
	[HotlineService registerService];
}

- (void)installLibpurplePlugin
{
	purple_init_hotline_plugin();
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
