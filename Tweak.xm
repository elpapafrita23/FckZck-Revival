#import <Foundation/Foundation.h>
#include <substrate.h>
#import <CommonCrypto/CommonDigest.h>
#import <objc/runtime.h>
#import <Security/Security.h>

// ---- Configurable version ----------------------------------------------
// Read from /var/mobile/Library/Preferences/com.ifilipis.fckzck.plist
//   <key>version</key><string>2.26.38.74</string>
// Accepts "2.26.38.74" (4 parts) or "26.38.74" (3 parts, a leading 2 is added).
// The build hash is always the MD5 of the version string.
#define DEFAULT_VERSION @"2.26.38.74"
static NSString *gVersion = nil;
static NSString *gHash = nil;
static int gNum[4] = {2, 26, 38, 74};
// Experiment: drop an EMPTY <ref-cert> node from the pair-device request.
// Config key: <key>skipEmptyRefCert</key><true/> to turn it on.
static BOOL gSkipEmptyRefCert = NO;  // default OFF = stock behaviour (skipping did not fix the 400)
// Experiment: OS version declared to the server in ClientPayload.UserAgent.
// Config keys (strings): osVersion, osBuildNumber. An EMPTY osVersion disables
// the override (the real iOS version is sent).
static NSString *gOsVersion = @"15.8.3";
static NSString *gOsBuild = @"19H386";

// ---- File logging -------------------------------------------------------
// Writes to <app Documents>/fckzck.log (and NSLog). Lets you read the log with
// Filza, no computer needed. The file is reset on every launch and capped.
static void FZLog(NSString *line) {
    NSLog(@"%@", line);
    static dispatch_queue_t queue;
    static NSString *path;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        queue = dispatch_queue_create("fckzck.log", DISPATCH_QUEUE_SERIAL);
        NSArray *dirs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
        path = [[dirs firstObject] stringByAppendingPathComponent:@"fckzck.log"];
        [@"" writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
    });
    dispatch_async(queue, ^{
        if (!path) return;
        NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:nil];
        if ([attrs fileSize] > 1500000) {
            [@"" writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
        }
        NSString *text = [NSString stringWithFormat:@"[%@] %@\n", [NSDate date], line];
        NSFileHandle *h = [NSFileHandle fileHandleForWritingAtPath:path];
        [h seekToEndOfFile];
        [h writeData:[text dataUsingEncoding:NSUTF8StringEncoding]];
        [h closeFile];
    });
}
#define FZ(fmt, ...) FZLog([NSString stringWithFormat:fmt, ##__VA_ARGS__])
// -------------------------------------------------------------------------

static NSString *FZMD5(NSString *text) {
    const char *c = [text UTF8String];
    unsigned char d[CC_MD5_DIGEST_LENGTH];
    CC_MD5(c, (CC_LONG)strlen(c), d);
    NSMutableString *out = [NSMutableString string];
    for (int i = 0; i < CC_MD5_DIGEST_LENGTH; i++) [out appendFormat:@"%02x", d[i]];
    return out;
}

static void FZLoadConfig(void) {
    NSString *wanted = DEFAULT_VERSION;
    NSDictionary *cfg = [NSDictionary dictionaryWithContentsOfFile:@"/var/mobile/Library/Preferences/com.ifilipis.fckzck.plist"];
    NSString *v = cfg[@"version"];
    id skip = cfg[@"skipEmptyRefCert"];
    if ([skip respondsToSelector:@selector(boolValue)]) gSkipEmptyRefCert = [skip boolValue];
    id ov = cfg[@"osVersion"];
    if ([ov isKindOfClass:[NSString class]]) gOsVersion = [(NSString *)ov length] ? ov : nil;
    id ob = cfg[@"osBuildNumber"];
    if ([ob isKindOfClass:[NSString class]]) gOsBuild = [(NSString *)ob length] ? ob : nil;
    if (!gOsVersion) gOsBuild = nil;
    FZ(@"FckZck: osVersion override=%@ osBuildNumber override=%@", gOsVersion ? gOsVersion : @"(off)", gOsBuild ? gOsBuild : @"(off)");
    if ([v isKindOfClass:[NSString class]] && v.length) wanted = v;
    else FZ(@"FckZck: no config found, using default version");

    NSMutableArray *parts = [[wanted componentsSeparatedByString:@"."] mutableCopy];
    if (parts.count == 3) [parts insertObject:@"2" atIndex:0];
    BOOL ok = (parts.count == 4);
    int nums[4] = {0, 0, 0, 0};
    for (NSUInteger i = 0; ok && i < 4; i++) {
        NSString *p = parts[i];
        NSScanner *sc = [NSScanner scannerWithString:p];
        int n = 0;
        if (![sc scanInt:&n] || ![sc isAtEnd] || n < 0) ok = NO; else nums[i] = n;
    }
    if (!ok) {
        FZ(@"FckZck: invalid version '%@', using default", wanted);
        wanted = DEFAULT_VERSION;
        parts = [[wanted componentsSeparatedByString:@"."] mutableCopy];
        for (int i = 0; i < 4; i++) nums[i] = [parts[i] intValue];
    }
    for (int i = 0; i < 4; i++) gNum[i] = nums[i];
    gVersion = [NSString stringWithFormat:@"%d.%d.%d.%d", nums[0], nums[1], nums[2], nums[3]];
    gHash = FZMD5(gVersion);
    FZ(@"FckZck: spoofing version %@ (hash %@)", gVersion, gHash);
}


// FckZck - keeps WhatsApp alive on old iOS versions.
// Original tweak by ifilipis. Continued with the platform-deprecation fix.


static NSDate * (*_orig_WAAppExpirationDate)();
static NSDate * (*_orig_WADeprecatedPlatformCutOffDate)();
static NSDate * (*_orig_WABuildDate)();
static NSString * (*_orig_WABuildVersion)(void *, void *);
static NSString * (*_orig_WABuildHash)();
static BOOL (*_orig_WAIsPlatformDeprecated)(void);
static BOOL (*_orig_WAShouldShowPlatformDeprecationNags)(void);

static NSDate *_new_WAAppExpirationDate() {
    FZ(@"_new_WAAppExpirationDate called");
    return [NSDate dateWithTimeIntervalSinceNow:31536000];
}

static NSDate *_new_WADeprecatedPlatformCutOffDate() {
    FZ(@"_new_WADeprecatedPlatformCutOffDate called");
    return [NSDate dateWithTimeIntervalSinceNow:31536000];
}

static NSDate *_new_WABuildDate() {
    FZ(@"_new_WABuildDate called");
    return [NSDate date];
}

static NSString *_new_WABuildVersion(void *arg1, void *arg2) {
    FZ(@"_new_WABuildVersion called");
    return gVersion;
}

static NSString *_new_WABuildHash() {
    FZ(@"_new_WABuildHash called");
    return gHash;
}

// The platform-deprecation check: the app asks "is this OS too old?" and,
// if so, shows the "update WhatsApp" wall. We always answer NO.
static BOOL _new_WAIsPlatformDeprecated(void) {
    FZ(@"_new_WAIsPlatformDeprecated called -> NO");
    return NO;
}

static BOOL _new_WAShouldShowPlatformDeprecationNags(void) {
    FZ(@"_new_WAShouldShowPlatformDeprecationNags called -> NO");
    return NO;
}

// Looks a symbol up in SharedModules and hooks it. Symbols there are prefixed
// with an underscore and must be looked up in that image, not with a NULL image
// (that is why the old commented-out WAIsPlatformDeprecated hook never worked).
static void hookSymbol(MSImageRef image, const char *name, void *replacement, void **original) {
    void *symbol = MSFindSymbol(image, name);
    if (symbol) {
        MSHookFunction(symbol, replacement, original);
        FZ(@"FckZck: hooked %s", name);
    } else {
        FZ(@"FckZck: failed to find %s", name);
    }
}

// ---- Stanza / pairing inspection ------------------------------------------
// Logs the structure of "iq ns=md" stanzas and every iq error (tags, attribute
// names/values, and byte LENGTHS of binary payloads -- never the bytes). Digit
// runs of 6+ (phone numbers, ids) are masked as '#'.
@protocol FZElem <NSObject>
- (NSString *)name;
- (NSDictionary *)attributesStringDictionary;
- (NSArray *)children;
- (NSData *)dataValue;
@end

static NSString *FZMask(NSString *s) {
    if (!s) return @"";
    static NSRegularExpression *re;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        re = [NSRegularExpression regularExpressionWithPattern:@"[0-9]{6,}" options:0 error:nil];
    });
    return [re stringByReplacingMatchesInString:s options:0 range:NSMakeRange(0, s.length) withTemplate:@"#"];
}

static NSString *FZDesc(id o) {
    if (!o) return @"nil";
    if ([o isKindOfClass:[NSData class]]) return [NSString stringWithFormat:@"NSData(%lu bytes)", (unsigned long)[(NSData *)o length]];
    if ([o isKindOfClass:[NSString class]]) return [NSString stringWithFormat:@"NSString(%lu chars)", (unsigned long)[(NSString *)o length]];
    NSString *x = [NSString stringWithFormat:@"%@", o];
    if (x.length > 400) x = [x substringToIndex:400];
    return [NSString stringWithFormat:@"%@ %@", NSStringFromClass([o class]), FZMask(x)];
}

static void FZDumpElem(id<FZElem> e, int depth, NSMutableString *out) {
    if (!e || depth > 8) return;
    NSString *indent = [@"" stringByPaddingToLength:(NSUInteger)(depth * 2) withString:@" " startingAtIndex:0];
    NSMutableString *attrs = [NSMutableString string];
    NSDictionary *d = [e respondsToSelector:@selector(attributesStringDictionary)] ? [e attributesStringDictionary] : nil;
    for (id k in d) {
        NSString *v = [NSString stringWithFormat:@"%@", d[k]];
        if (v.length > 60) v = [[v substringToIndex:60] stringByAppendingString:@"..."];
        [attrs appendFormat:@" %@=\"%@\"", k, FZMask(v)];
    }
    NSData *data = [e respondsToSelector:@selector(dataValue)] ? [e dataValue] : nil;
    NSString *dstr = data.length ? [NSString stringWithFormat:@" [%lu bytes]", (unsigned long)data.length] : @"";
    [out appendFormat:@"%@<%@%@>%@\n", indent, [e name], attrs, dstr];
    NSArray *kids = [e respondsToSelector:@selector(children)] ? [e children] : nil;
    for (id c in kids) FZDumpElem((id<FZElem>)c, depth + 1, out);
}
// -------------------------------------------------------------------------

// ---- Class dump (discovery) -----------------------------------------------
// 20 s after launch, writes the names + method selectors + type encodings of
// every class related to pairing / companion / ADV / stanzas to
// <app Documents>/fckzck-classes.txt. Only in the main WhatsApp apps.
static void FZDumpClasses(void) {
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
    if (![bid isEqualToString:@"net.whatsapp.WhatsApp"] && ![bid isEqualToString:@"net.whatsapp.WhatsAppSMB"]) return;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(20 * NSEC_PER_SEC)),
                   dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSArray *pats = @[@"Pair", @"Companion", @"ADV", @"DeviceProps", @"DeviceIdentity",
                          @"WAWebClient", @"LinkedDevice", @"LinkCode", @"Stanza",
                          @"PreKey", @"SignedPreKey", @"SignalStore", @"SignalSession", @"IdentityStore"];
        NSMutableString *out = [NSMutableString string];
        unsigned int n = 0;
        Class *classes = objc_copyClassList(&n);
        for (unsigned int i = 0; i < n; i++) {
            const char *cn = class_getName(classes[i]);
            if (!cn) continue;
            NSString *name = [NSString stringWithUTF8String:cn];
            if (!name) continue;
            BOOL hit = NO;
            for (NSString *p in pats) {
                if ([name rangeOfString:p].location != NSNotFound) { hit = YES; break; }
            }
            if (!hit) continue;
            Class sup = class_getSuperclass(classes[i]);
            [out appendFormat:@"\n@%@ : %s\n", name, sup ? class_getName(sup) : "-"];
            unsigned int mc = 0;
            Method *ms = class_copyMethodList(classes[i], &mc);
            for (unsigned int j = 0; j < mc; j++) {
                const char *enc = method_getTypeEncoding(ms[j]);
                [out appendFormat:@"  - %s  %s\n", sel_getName(method_getName(ms[j])), enc ? enc : ""];
            }
            free(ms);
            if (out.length > 1500000) break;
        }
        free(classes);
        NSArray *dirs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
        NSString *path = [[dirs firstObject] stringByAppendingPathComponent:@"fckzck-classes.txt"];
        [out writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
        FZ(@"FckZck: class dump written (%lu bytes)", (unsigned long)out.length);
    });
}
// -------------------------------------------------------------------------

// ---- ClientPayload.UserAgent OS-version experiment -------------------------
static void (*orig_setOsVersion)(id, SEL, id);
static void new_setOsVersion(id self, SEL _cmd, id v) {
    FZ(@"FckZck: UserAgent.setOsVersion(%@) -> %@", v, gOsVersion ? gOsVersion : @"(unchanged)");
    orig_setOsVersion(self, _cmd, gOsVersion ? gOsVersion : v);
}

static void (*orig_setOsBuildNumber)(id, SEL, id);
static void new_setOsBuildNumber(id self, SEL _cmd, id v) {
    FZ(@"FckZck: UserAgent.setOsBuildNumber(%@) -> %@", v, gOsBuild ? gOsBuild : @"(unchanged)");
    orig_setOsBuildNumber(self, _cmd, gOsBuild ? gOsBuild : v);
}

static void (*orig_setDevice)(id, SEL, id);
static void new_setDevice(id self, SEL _cmd, id v) {
    FZ(@"FckZck: UserAgent.setDevice(%@)", v);
    orig_setDevice(self, _cmd, v);
}

static void (*orig_setManufacturer)(id, SEL, id);
static void new_setManufacturer(id self, SEL _cmd, id v) {
    FZ(@"FckZck: UserAgent.setManufacturer(%@)", v);
    orig_setManufacturer(self, _cmd, v);
}

static void FZHookSetter(Class c, const char *selName, IMP repl, IMP *orig) {
    SEL sel = sel_registerName(selName);
    Method m = class_getInstanceMethod(c, sel);
    if (!m) { FZ(@"FckZck: UserAgent has no %s", selName); return; }
    const char *enc = method_getTypeEncoding(m);
    if (!enc || strcmp(enc, "v24@0:8@16") != 0) {
        FZ(@"FckZck: UserAgent %s has unexpected type %s, not hooked", selName, enc ? enc : "?");
        return;
    }
    MSHookMessageEx(c, sel, repl, orig);
    FZ(@"FckZck: hooked UserAgent %s", selName);
}

static BOOL FZInstallUserAgentHooks(void) {
    Class c = objc_getClass("WAPBClientPayload_UserAgent");
    if (!c) return NO;
    unsigned int mc = 0;
    Method *ms = class_copyMethodList(c, &mc);
    NSMutableArray *names = [NSMutableArray array];
    for (unsigned int j = 0; j < mc; j++) {
        const char *n = sel_getName(method_getName(ms[j]));
        if (strncmp(n, "set", 3) == 0) {
            const char *enc = method_getTypeEncoding(ms[j]);
            [names addObject:[NSString stringWithFormat:@"%s(%s)", n, enc ? enc : ""]];
        }
    }
    free(ms);
    FZ(@"FckZck: UserAgent setters: %@", [names componentsJoinedByString:@" "]);
    FZHookSetter(c, "setOsVersion:", (IMP)new_setOsVersion, (IMP *)&orig_setOsVersion);
    FZHookSetter(c, "setOsBuildNumber:", (IMP)new_setOsBuildNumber, (IMP *)&orig_setOsBuildNumber);
    FZHookSetter(c, "setDevice:", (IMP)new_setDevice, (IMP *)&orig_setDevice);
    FZHookSetter(c, "setManufacturer:", (IMP)new_setManufacturer, (IMP *)&orig_setManufacturer);
    return YES;
}
// -------------------------------------------------------------------------

// ---- Keychain failure logging (diagnostic) ---------------------------------
// Logs service/account/access-group and OSStatus of failed SecItemAdd/Update.
// Never logs secret values. Duplicate-item (-25299) is normal noise.
static OSStatus (*orig_SecItemAdd)(CFDictionaryRef, CFTypeRef *);
static OSStatus new_SecItemAdd(CFDictionaryRef attrs, CFTypeRef *result) {
    OSStatus st = orig_SecItemAdd(attrs, result);
    if (st != errSecSuccess && st != errSecDuplicateItem) {
        NSDictionary *d = (__bridge NSDictionary *)attrs;
        FZ(@"FckZck: SecItemAdd FAILED status=%d svce=%@ acct=%@ agrp=%@", (int)st,
           d[(__bridge id)kSecAttrService], d[(__bridge id)kSecAttrAccount], d[(__bridge id)kSecAttrAccessGroup]);
    }
    return st;
}

static OSStatus (*orig_SecItemUpdate)(CFDictionaryRef, CFDictionaryRef);
static OSStatus new_SecItemUpdate(CFDictionaryRef query, CFDictionaryRef upd) {
    OSStatus st = orig_SecItemUpdate(query, upd);
    if (st != errSecSuccess && st != errSecItemNotFound) {
        NSDictionary *d = (__bridge NSDictionary *)query;
        FZ(@"FckZck: SecItemUpdate FAILED status=%d svce=%@ acct=%@ agrp=%@", (int)st,
           d[(__bridge id)kSecAttrService], d[(__bridge id)kSecAttrAccount], d[(__bridge id)kSecAttrAccessGroup]);
    }
    return st;
}
// -------------------------------------------------------------------------

%ctor {
    FZLoadConfig();
    FZ(@"FckZck 1.8.0 loaded in %@", [[NSBundle mainBundle] bundleIdentifier]);
    if (!FZInstallUserAgentHooks()) {
        FZ(@"FckZck: WAPBClientPayload_UserAgent not found yet, retrying in 3s");
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            if (!FZInstallUserAgentHooks()) FZ(@"FckZck: WAPBClientPayload_UserAgent still not found");
        });
    }
    MSHookFunction((void *)SecItemAdd, (void *)new_SecItemAdd, (void **)&orig_SecItemAdd);
    MSHookFunction((void *)SecItemUpdate, (void *)new_SecItemUpdate, (void **)&orig_SecItemUpdate);
    FZDumpClasses();
    NSString *bundlePath = [[NSBundle mainBundle] bundlePath];
    NSString *frameworkPath = [bundlePath stringByAppendingPathComponent:@"Frameworks/SharedModules.framework/SharedModules"];
    MSImageRef image = MSGetImageByName([frameworkPath UTF8String]);

    if (!image) {
        FZ(@"FckZck: failed to load image at path: %@", frameworkPath);
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
	static NSArray *keys;
	static dispatch_once_t once;
	dispatch_once(&once, ^{
		keys = @[@"md/", @"pair", @"link", @"companion", @"gcm", @"xmpp//", @"stream//", @"LL_E", @"LL_W", @"login", @"auth", @"deprecat", @"expire", @"version"];
	});
	for (NSString *k in keys) {
		if ([result rangeOfString:k options:NSCaseInsensitiveSearch].location != NSNotFound) {
			FZ(@"WALog: %@", result);
			break;
		}
	}
	return result;
}

%end

%hook WAPBClientPayload_UserAgent_AppVersion

-(void)setPrimary:(int)i {
	%orig(gNum[0]);
}

-(void)setSecondary:(int)i {
	%orig(gNum[1]);
}

-(void)setTertiary:(int)i {
	%orig(gNum[2]);
}

-(void)setQuaternary:(int)i {
	%orig(gNum[3]);
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

%hook XMPPIQStanza

-(NSString *)log {
    NSString *r = %orig;
    @try {
        if (r && ([r rangeOfString:@"ns=md"].location != NSNotFound || [r rangeOfString:@"iq/error"].location != NSNotFound)) {
            NSMutableString *out = [NSMutableString stringWithFormat:@"STANZA %@\n", FZMask(r)];
            FZDumpElem((id<FZElem>)self, 1, out);
            FZ(@"FckZck: %@", out);
        }
    } @catch (NSException *e) {}
    return r;
}

%end

%hook WADevicePairingSession

- (void)devicePairingSession:(id)session didRequestPairDeviceWithRef:(id)ref authKey:(id)authKey identityKey:(id)identityKey hmacSignedDeviceIdentity:(id)hmac keyIndexList:(id)keyIndexList refCert:(id)refCert clientProps:(id)clientProps completion:(id)completion {
    FZ(@"FckZck: PAIR request ref=%@ authKey=%@ identityKey=%@ hmacSignedDeviceIdentity=%@ keyIndexList=%@ refCert=%@ clientProps=%@",
       FZDesc(ref), FZDesc(authKey), FZDesc(identityKey), FZDesc(hmac), FZDesc(keyIndexList), FZDesc(refCert), FZDesc(clientProps));
    %orig;
}

- (void)handlePairDeviceResponseWithDeviceJID:(id)jid companionProps:(id)companionProps retryTimestamp:(unsigned long long)ts serverError:(id)serverError {
    FZ(@"FckZck: PAIR response jid=%@ companionProps=%@ retryTimestamp=%llu serverError=%@",
       FZDesc(jid), FZDesc(companionProps), ts, FZDesc(serverError));
    %orig;
}

%end

%hook XMPPStanzaElement

-(void)addChildWithName:(id)name dataValue:(id)data {
    @try {
        if ([name isKindOfClass:[NSString class]] && ([name isEqualToString:@"ref-cert"] || [name isEqualToString:@"client-props"])) {
            NSUInteger len = [data isKindOfClass:[NSData class]] ? [(NSData *)data length] : 0;
            NSString *hex = (len > 0 && len <= 4) ? [NSString stringWithFormat:@" bytes=%@", [(NSData *)data description]] : @"";
            FZ(@"FckZck: addChildWithName %@ dataValue=%lu bytes%@", name, (unsigned long)len, hex);
            if (len == 0 && gSkipEmptyRefCert && [name isEqualToString:@"ref-cert"]) {
                FZ(@"FckZck: skipped empty ref-cert");
                return;
            }
        }
    } @catch (NSException *e) {}
    %orig;
}

-(void)addChild:(id)child {
    @try {
        if (child) {
            NSString *n = [(id<FZElem>)child name];
            if ([n isEqualToString:@"ref-cert"] || [n isEqualToString:@"client-props"]) {
                NSData *d = [(id<FZElem>)child dataValue];
                NSUInteger kids = [[(id<FZElem>)child children] count];
                NSString *hex = (d.length > 0 && d.length <= 4) ? [NSString stringWithFormat:@" bytes=%@", d] : @"";
                FZ(@"FckZck: addChild %@ dataValue=%lu bytes children=%lu%@", n, (unsigned long)d.length, (unsigned long)kids, hex);
                if (gSkipEmptyRefCert && [n isEqualToString:@"ref-cert"] && d.length == 0 && kids == 0) {
                    FZ(@"FckZck: skipped empty ref-cert");
                    return;
                }
            }
        }
    } @catch (NSException *e) {}
    %orig;
}

%end
