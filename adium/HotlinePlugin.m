/*
 * purple-hotline for Adium: registers the libpurple protocol and Adium's service
 * for it. Copyright (c) 2026 John Leighow. MIT license.
 */
#import "HotlinePlugin.h"
#import "HotlineService.h"

#include <glib.h>

extern gboolean purple_init_hotline_plugin(void);

#ifndef HL_ADIUM_13
#import <objc/runtime.h>

/* Adium 1.5's chat windows stop scrolling down on recent macOS: its page template
 * reads and sets document.body.scrollTop, which newer WebKit ignores (the page's
 * scrolling element is the document now). Every chat page is built by
 * -[AIWebkitMessageViewStyle baseTemplateForChat:], so the template is mended there,
 * for every service and message style: (document.scrollingElement || document.body)
 * is the right element on old and new WebKit alike. Tiger's WebKit doesn't need it. */
static IMP originalBaseTemplate;

static NSString *mendedBaseTemplate(id self, SEL _cmd, id chat)
{
	NSString *html = ((NSString *(*)(id, SEL, id))originalBaseTemplate)(self, _cmd, chat);
	if (![html isKindOfClass:[NSString class]])
		return html;
	return [html stringByReplacingOccurrencesOfString:@"document.body.scrollTop"
	                                        withString:@"(document.scrollingElement || document.body).scrollTop"];
}

static void mendChatScrolling(void)
{
	Class style = NSClassFromString(@"AIWebkitMessageViewStyle");
	Method m = style ? class_getInstanceMethod(style, @selector(baseTemplateForChat:)) : NULL;
	if (m && !originalBaseTemplate)
		originalBaseTemplate = method_setImplementation(m, (IMP)mendedBaseTemplate);
	NSLog(@"Hotline: chat window scrolling %@", m ? @"mended" : @"left alone (no message style class)");
}
#endif

@implementation HotlinePlugin

/* The service is Adium's, so it's registered as soon as the bundle loads. The protocol
 * is libpurple's: Adium 1.5 takes it right away (as other plugins do), but Adium 1.3
 * loads bundles before libpurple starts, so there it waits (build-tiger.sh sets
 * HL_ADIUM_13). */
- (void)installPlugin
{
#ifndef HL_ADIUM_13
	purple_init_hotline_plugin();
	mendChatScrolling();
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
