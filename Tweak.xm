#import <Foundation/Foundation.h>
#include <substrate.h>

// FckZck - keeps WhatsApp alive on old iOS versions.
// Original tweak by ifilipis. Continued with the platform-deprecation fix.

#define NEW_VERSION_STRING @"2.26.38.74"
#define NEW_BUILD_HASH     @"3b7b0251498d77ec4073784cd5d07d47" // md5 of NEW_VERSION_STRING

static NSDate * (*_orig_WAAppExpirationDate)();
static NSDate * (*_orig_WADeprecatedPlatformCutOffDate)();
static NSDate * (*_orig_WABuildDate)();
static NSString * (*_orig_WABuildVersion)(void *, void *);
static NSString * (*_orig_WABuildHash)();
static BOOL (*_orig_WAIsPlatformDeprecated)(void);
static BOOL (*_orig_WAShouldShowPlatformDeprecationNags)(void);

static NSDate *_new_WAAppExpirationDate() {
    NSLog(@"_new_WAAppExpirationDate called");
    return [NSDate dateWithTimeIntervalSinceNow:31536000];
}

static NSDate *_new_WADeprecatedPlatformCutOffDate() {
    NSLog(@"_new_WADeprecatedPlatformCutOffDate called");
    return [NSDate dateWithTimeIntervalSinceNow:31536000];
}

static NSDate *_new_WABuildDate() {
    NSLog(@"_new_WABuildDate called");
    return [NSDate date];
}

static NSString *_new_WABuildVersion(void *arg1, void *arg2) {
    NSLog(@"_new_WABuildVersion called");
    return NEW_VERSION_STRING;
}

static NSString *_new_WABuildHash() {
    NSLog(@"_new_WABuildHash called");
    return NEW_BUILD_HASH;
}

// The platform-deprecation check: the app asks "is this OS too old?" and,
// if so, shows the "update WhatsApp" wall. We always answer NO.
static BOOL _new_WAIsPlatformDeprecated(void) {
    NSLog(@"_new_WAIsPlatformDeprecated called -> NO");
    return NO;
}

static BOOL _new_WAShouldShowPlatformDeprecationNags(void) {
    NSLog(@"_new_WAShouldShowPlatformDeprecationNags called -> NO");
    return NO;
}

// Looks a symbol up in SharedModules and hooks it. Symbols there are prefixed
// with an underscore and must be looked up in that image, not with a NULL image
// (that is why the old commented-out WAIsPlatformDeprecated hook never worked).
static void hookSymbol(MSImageRef image, const char *name, void *replacement, void **original) {
    void *symbol = MSFindSymbol(image, name);
    if (symbol) {
        MSHookFunction(symbol, replacement, original);
        NSLog(@"FckZck: hooked %s", name);
    } else {
        NSLog(@"FckZck: failed to find %s", name);
    }
}

%ctor {
    // Activa los %hook de clases (obligatorio cuando se define un %ctor propio)
    %init;

    NSString *bundlePath = [[NSBundle mainBundle] bundlePath];
    NSString *frameworkPath = [bundlePath stringByAppendingPathComponent:@"Frameworks/SharedModules.framework/SharedModules"];
    MSImageRef image = MSGetImageByName([frameworkPath UTF8String]);

    if (!image) {
        NSLog(@"FckZck: failed to load image at path: %@", frameworkPath);
        return;
    }

    hookSymbol(image, "_WAAppExpirationDate", (void *)&_new_WAAppExpirationDate, (void **)&_orig_WAAppExpirationDate);
    hookSymbol(image, "_WABuildDate", (void *)&_new_WABuildDate, (void **)&_orig_WABuildDate);
    hookSymbol(image, "_WABuildVersion", (void *)&_new_WABuildVersion, (void **)&_orig_WABuildVersion);
    hookSymbol(image, "_WABuildHash", (void *)&_new_WABuildHash, (void **)&_orig_WABuildHash);
    hookSymbol(image, "_WADeprecatedPlatformCutOffDate", (void *)&_new_WADeprecatedPlatformCutOffDate, (void **)&_orig_WADeprecatedPlatformCutOffDate);
    hookSymbol(image, "_WAIsPlatformDeprecated", (void *)&_new_WAIsPlatformDeprecated, (void **)&_orig_WAIsPlatformDeprecated);
    hookSymbol(image, "_WAShouldShowPlatformDeprecationNags", (void *)&_new_WAShouldShowPlatformDeprecationNags, (void **)&_orig_WAShouldShowPlatformDeprecationNags);
}

%hook WALogWriter

-(NSString*)formatLogText:(NSString*)ar1 withLevel:(int)ar2 {
	NSString *result = %orig;
	NSLog(@"WALog: %@", result);
	return result;
}

%end

%hook WAPBClientPayload_UserAgent_AppVersion

-(void)setPrimary:(int)i {
	%orig(2);
}

-(void)setSecondary:(int)i {
	%orig(26);
}

-(void)setTertiary:(int)i {
	%orig(38);
}

-(void)setQuaternary:(int)i {
	%orig(74);
}

%end

%hook WARootViewController

-(bool)isBuildExpired {
    return false;
}

%end

%hook WAMessage

-(bool)needsLocalNotification {
    return true;
}

%end
