#import <Foundation/Foundation.h>
#include <substrate.h>
#import <CommonCrypto/CommonDigest.h>
#import <objc/runtime.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <malloc/malloc.h>
#include <stdlib.h>

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
static NSString *gHistoryMode = @"stock";
static NSNumber *gForceSyncState = nil;  // 1.20 diagnostic: observe the real UI state; do not force it.
// Experiment (1.11): the app logs itself out ~120 s after pairing because history sync never
// completes (reason "history_sync_timeout"). When ON, that single logout is swallowed and the
// bootstrap is told the initial history sync finished instead.
// Config keys: blockHistoryTimeoutLogout (bool, default ON),
//              historyTimeoutRemovalReason (integer, default 11 = value seen in log 2).
static BOOL gBlockHistoryTimeoutLogout = YES; // 1.26: safety net, swallow the history_sync_timeout logout (reason 11).
// Experiment (1.12): force WASignalAddress "deprecated" for individual (non-group) sessions.
// -1 = leave as is, 0 = force NO (default), 1 = force YES. Config key: signalDeprecatedOverride (integer).
static int gDeprecatedOverride = 0;
// Experiment (1.17): the app keeps the primary\'s Signal session under its LID address, but some
// messages from the same sender arrive addressed by phone number (PN) and look for a session
// that does not exist (-> missing one-time prekey, -1003). When a PN decrypt fails, retry it with
// the LID addresses that already decrypted something. A successful decrypt proves the identity, so
// the PN->LID pair is then remembered. Config key: lidFallback (bool, default ON).
static BOOL gLidFallback = YES;
// Experiment (1.13): if the bootstrap ("loading your chats") has not been told that the initial
// history sync finished N seconds after pairing, tell it ourselves. 0 = off.
// Config key: forceFinishBootstrapSeconds (integer).
static int gForceFinishSeconds = 0; // 1.28.1: disabled; never force bootstrap completion.
// 1.19 test: make the companion service report initial history sync as finished.
static BOOL gInitialCalled = NO;
static BOOL gSecCalled = NO;
static __weak id gHistSvc = nil;
static long long gBlockLogoutReason = 11;
static BOOL gSkipEmptyRefCert = YES; // 1.28.2: omit malformed empty ref-cert from pair-device
// Experiment: OS version declared to the server in ClientPayload.UserAgent.
// Config keys (strings): osVersion, osBuildNumber. An EMPTY osVersion disables
// the override (the real iOS version is sent).
static BOOL gReqFullSync = YES;   // 1.27: ask the phone for full history at pairing
static int gHistDays = 365;       // 1.27: days of history requested
static NSString *gOsVersion = nil;
static NSString *gOsBuild = nil;

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
        // keep the last launches as fckzck-<yyyyMMdd-HHmmss>.log (newest 6) instead of wiping the log
        NSString *dir = [dirs firstObject];
        NSFileManager *fm = [NSFileManager defaultManager];
        [fm removeItemAtPath:[dir stringByAppendingPathComponent:@"fckzck-prev.log"] error:nil];
        if ([fm fileExistsAtPath:path]) {
            NSDate *m = [[fm attributesOfItemAtPath:path error:nil] fileModificationDate];
            if (!m) m = [NSDate date];
            NSDateFormatter *df = [[NSDateFormatter alloc] init];
            df.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
            df.dateFormat = @"yyyyMMdd-HHmmss";
            NSString *arch = [dir stringByAppendingPathComponent:[NSString stringWithFormat:@"fckzck-%@.log", [df stringFromDate:m]]];
            [fm moveItemAtPath:path toPath:arch error:nil];
        }
        NSMutableArray *olds = [NSMutableArray array];
        for (NSString *f in [fm contentsOfDirectoryAtPath:dir error:nil]) {
            if ([f hasPrefix:@"fckzck-2"] && [f hasSuffix:@".log"]) [olds addObject:f];
        }
        [olds sortUsingSelector:@selector(compare:)];
        while (olds.count > 6) {
            [fm removeItemAtPath:[dir stringByAppendingPathComponent:olds.firstObject] error:nil];
            [olds removeObjectAtIndex:0];
        }
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
    // 1.26: the 120 s history_sync_timeout logout is blocked by default (plist key
    // blockHistoryTimeoutLogout can turn it off) and the bootstrap is completed by hand.
    gBlockHistoryTimeoutLogout = YES;
    id bl = cfg[@"blockHistoryTimeoutLogout"];
    if ([bl respondsToSelector:@selector(boolValue)]) gBlockHistoryTimeoutLogout = [bl boolValue];
    gBlockLogoutReason = 11;
    FZ(@"FckZck 1.28.2: blockHistoryTimeoutLogout=%d reason=%lld", gBlockHistoryTimeoutLogout, gBlockLogoutReason);
    gForceFinishSeconds = 0;
    FZ(@"FckZck 1.28.2: forceFinishBootstrapSeconds=0 (fixed off)");
    FZ(@"FckZck 1.28.2: skipEmptyRefCert=%d (pairing fix)", gSkipEmptyRefCert);
    id rf = cfg[@"requireFullSync"];
    if ([rf respondsToSelector:@selector(boolValue)]) gReqFullSync = [rf boolValue];
    id hd = cfg[@"historyDays"];
    if ([hd isKindOfClass:[NSNumber class]]) gHistDays = [hd intValue];
    FZ(@"FckZck 1.27: requireFullSync=%d historyDays=%d", gReqFullSync, gHistDays);
    id so = cfg[@"signalDeprecatedOverride"];
    if ([so isKindOfClass:[NSNumber class]]) gDeprecatedOverride = [so intValue];
    FZ(@"FckZck: signalDeprecatedOverride=%d", gDeprecatedOverride);
    id lf = cfg[@"lidFallback"];
    if ([lf respondsToSelector:@selector(boolValue)]) gLidFallback = [lf boolValue];
    FZ(@"FckZck: lidFallback=%d", gLidFallback);
    // Keep stock failure handling; the compatibility path is only activated
    // when runWhenInitialSyncFinished is actually reached.
    gHistoryMode = @"stock";
    FZ(@"FckZck 1.28.2: historySyncFailureMode=%@ (fixed)", gHistoryMode);
    id fs = cfg[@"forceSyncState"];
    if ([fs isKindOfClass:[NSNumber class]]) { gForceSyncState = fs; FZ(@"FckZck: forceSyncState=%@", fs); } else { FZ(@"FckZck: forceSyncState default=%@", gForceSyncState); }
    // Never consume legacy osVersion/osBuildNumber plist overrides.
    gOsVersion = nil;
    gOsBuild = nil;
    FZ(@"FckZck 1.28.2: osVersion override=(off) osBuildNumber override=(off) (fixed)");
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
__attribute__((unused)) static void FZDumpClassesMatching(NSArray *pats, NSString *fname) {
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
    if (![bid isEqualToString:@"net.whatsapp.WhatsApp"] && ![bid isEqualToString:@"net.whatsapp.WhatsAppSMB"]) return;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(20 * NSEC_PER_SEC)),
                   dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
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
        NSString *path = [[dirs firstObject] stringByAppendingPathComponent:fname];
        [out writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
        FZ(@"FckZck: class dump %@ written (%lu bytes)", fname, (unsigned long)out.length);
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
    static int stackN = 0;
    if (stackN++ < 3) {
        NSArray *st = [NSThread callStackSymbols];
        for (NSUInteger i = 0; i < st.count && i < 30; i++) FZ(@"FckZck 1.27: STACK#%d %@", stackN, st[i]);
    }
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

// ---- History-sync bootstrap (companion login) -------------------------------
// Log 5: pairing + app-state sync work, but history sync never starts and after
// ~120 s the app logs itself out ("history_sync_timeout"). These hooks (a) log
// what the history-sync service receives and (b) change what happens on failure.
// Config key historySyncFailureMode (string):
//   "continue" (default) - on failure behave as if the initial sync finished
//   "ignore"             - on failure do nothing (loading screen may stay)
//   "stock"              - original behaviour (logout)
static void (*orig_hsInitial)(id, SEL);
static void new_hsInitial(id self, SEL _cmd) {
    FZ(@"FckZck: CompanionBootstrapLoading.handleInitialHistorySync called");
    gInitialCalled = YES;
    orig_hsInitial(self, _cmd);
}

static void (*orig_hsFailure)(id, SEL, id);
static void new_hsFailure(id self, SEL _cmd, id reason) {
    FZ(@"FckZck: CompanionBootstrapLoading.handleHistorySyncFailure(%@) mode=%@", FZDesc(reason), gHistoryMode);
    if ([gHistoryMode isEqualToString:@"stock"]) { orig_hsFailure(self, _cmd, reason); return; }
    if ([gHistoryMode isEqualToString:@"continue"] && orig_hsInitial) {
        FZ(@"FckZck: -> treating failure as finished (calling original handleInitialHistorySync)");
        orig_hsInitial(self, _cmd);
    } else {
        FZ(@"FckZck: -> failure ignored");
    }
}

static void (*orig_hsHandle)(id, SEL, id, id);
static void new_hsHandle(id self, SEL _cmd, id msg, id stanza) {
    gHistSvc = self;
    @try {
        NSMutableString *line = [NSMutableString stringWithFormat:@"FckZck: HistorySyncService.handleMessage class=%@", NSStringFromClass([msg class])];
        NSArray *paths = @[@"type",
                           @"historySyncNotification.syncType",
                           @"historySyncNotification.chunkOrder",
                           @"historySyncNotification.progress",
                           @"historySyncNotification.fileLength",
                           @"historySyncNotification.hasDirectPath",
                           @"historySyncNotification.hasInitialHistBootstrapInlinePayload",
                           @"appStateSyncKeyShare.keys.@count"];
        for (NSString *kp in paths) {
            id v = nil;
            @try { v = [msg valueForKeyPath:kp]; } @catch (NSException *e) { v = nil; }
            if ([v isKindOfClass:[NSNumber class]]) [line appendFormat:@" %@=%@", kp, v];
        }
        FZ(@"%@", line);
    } @catch (NSException *e) {}
    // 1.28.1: observe the notification only; never force bootstrap completion here.
    orig_hsHandle(self, _cmd, msg, stanza);

}

static void (*orig_preKeyFail)(id, SEL, id);
static void new_preKeyFail(id self, SEL _cmd, id err) {
    FZ(@"FckZck: CompanionRegistrationLogger.handlePreKeysUploadFail(%@)", FZDesc(err));
    orig_preKeyFail(self, _cmd, err);
}


// UI controller state (the 120 s history-sync timeout decides based on this).
// Logs every change of the value. Optional override via plist key
// forceSyncState (integer) to experiment with the "finished" value.
static long long (*orig_syncState)(id, SEL);
static long long new_syncState(id self, SEL _cmd) {
    long long v = orig_syncState(self, _cmd);
    static long long last = -9999;
    if (v != last) { FZ(@"FckZck: HistorySync UI currentSyncState=%lld", v); last = v; }
    if (gForceSyncState) return [gForceSyncState longLongValue];
    return v;
}


static BOOL FZHookIfPresent(Class c, const char *selName, const char *wantEnc, IMP repl, IMP *orig);

// 1.20 diagnostic hooks discovered from the class dump.
// These deliberately OBSERVE the real History Sync state; they do not force completion.
static BOOL (*orig_deviceInitial)(id, SEL);
static BOOL new_deviceInitial(id self, SEL _cmd) {
    BOOL v = orig_deviceInitial(self, _cmd);
    static int last = -1;
    if (last != (int)v) { last = (int)v; FZ(@"FckZck: HistorySyncDevice.isInitialSyncFinished=%d", v); }
    return v;
}

static BOOL (*orig_deviceSyncing)(id, SEL);
static BOOL new_deviceSyncing(id self, SEL _cmd) {
    BOOL v = orig_deviceSyncing(self, _cmd);
    static int last = -1;
    if (last != (int)v) { last = (int)v; FZ(@"FckZck: HistorySyncDevice.isSyncing=%d", v); }
    return v;
}

static BOOL (*orig_deviceCompleted)(id, SEL);
static BOOL new_deviceCompleted(id self, SEL _cmd) {
    BOOL v = orig_deviceCompleted(self, _cmd);
    static int last = -1;
    if (last != (int)v) { last = (int)v; FZ(@"FckZck: HistorySyncDevice.isCompleted=%d", v); }
    return v;
}

static unsigned int (*orig_initialState)(id, SEL);
static unsigned int new_initialState(id self, SEL _cmd) {
    unsigned int v = orig_initialState(self, _cmd);
    static unsigned int last = UINT_MAX;
    if (last != v) { last = v; FZ(@"FckZck: PBBProtoInitialSyncStateUpdate.state=%u", v); }
    return v;
}

static double (*orig_initialProgress)(id, SEL);
static double new_initialProgress(id self, SEL _cmd) {
    double v = orig_initialProgress(self, _cmd);
    static double last = -1.0;
    if (last < 0.0 || fabs(last - v) >= 0.01) { last = v; FZ(@"FckZck: PBBProtoInitialSyncStateUpdate.progress=%.4f", v); }
    return v;
}

static void (*orig_devicesModified)(id, SEL, id);
static void new_devicesModified(id self, SEL _cmd, id notification) {
    FZ(@"FckZck: HistorySyncCompanionDevicesListener.companionDevicesModifiedWithNotification=%@", FZDesc(notification));
    orig_devicesModified(self, _cmd, notification);
}

static void (*orig_pairingTimedOut)(id, SEL, id);
static void new_pairingTimedOut(id self, SEL _cmd, id notification) {
    FZ(@"FckZck: HistorySyncCompanionDevicesListener.companionPairingTimedOutWithNotification=%@", FZDesc(notification));
    orig_pairingTimedOut(self, _cmd, notification);
}

static BOOL FZInstallDiagnosticHistoryHooks(void) {
    Class device = objc_getClass("WAHistorySync.HistorySyncDevice");
    if (!device) device = objc_getClass("_TtC13WAHistorySync17HistorySyncDevice");
    if (device) {
        FZHookIfPresent(device, "isInitialSyncFinished", "B16@0:8", (IMP)new_deviceInitial, (IMP *)&orig_deviceInitial);
        FZHookIfPresent(device, "isSyncing", "B16@0:8", (IMP)new_deviceSyncing, (IMP *)&orig_deviceSyncing);
        FZHookIfPresent(device, "isCompleted", "B16@0:8", (IMP)new_deviceCompleted, (IMP *)&orig_deviceCompleted);
    } else FZ(@"FckZck: HistorySyncDevice not found");

    Class state = objc_getClass("PBBProtoInitialSyncStateUpdate");
    if (state) {
        FZHookIfPresent(state, "state", "I16@0:8", (IMP)new_initialState, (IMP *)&orig_initialState);
        FZHookIfPresent(state, "progress", "d16@0:8", (IMP)new_initialProgress, (IMP *)&orig_initialProgress);
    } else FZ(@"FckZck: PBBProtoInitialSyncStateUpdate not found");

    Class listener = objc_getClass("WAHistorySync.HistorySyncCompanionDevicesListener");
    if (!listener) listener = objc_getClass("_TtC13WAHistorySync34HistorySyncCompanionDevicesListener");
    if (listener) {
        FZHookIfPresent(listener, "companionDevicesModifiedWithNotification:", "v24@0:8@16", (IMP)new_devicesModified, (IMP *)&orig_devicesModified);
        FZHookIfPresent(listener, "companionPairingTimedOutWithNotification:", "v24@0:8@16", (IMP)new_pairingTimedOut, (IMP *)&orig_pairingTimedOut);
    } else FZ(@"FckZck: HistorySyncCompanionDevicesListener not found");
    return YES;
}

static BOOL FZHookIfPresent(Class c, const char *selName, const char *wantEnc, IMP repl, IMP *orig) {
    SEL sel = sel_registerName(selName);
    Method m = class_getInstanceMethod(c, sel);
    if (!m) { FZ(@"FckZck: %s has no %s", class_getName(c), selName); return NO; }
    const char *enc = method_getTypeEncoding(m);
    if (!enc || strcmp(enc, wantEnc) != 0) {
        FZ(@"FckZck: %s %s unexpected type %s, not hooked", class_getName(c), selName, enc ? enc : "?");
        return NO;
    }
    MSHookMessageEx(c, sel, repl, orig);
    FZ(@"FckZck: hooked %s %s", class_getName(c), selName);
    return YES;
}

// Remember the live CompanionBootstrapLoading object (it is called during pairing,
// well before the 120 s timeout fires).
@protocol FZSvc <NSObject>
- (BOOL)isInitialSyncFinished;
@end

// WAHistorySyncCompanionService: ObjC surface seen in log 5 (everything else is Swift).
static BOOL (*orig_isInit)(id, SEL);
static BOOL new_isInit(id self, SEL _cmd) {
    BOOL r = orig_isInit(self, _cmd);
    static int last = -1;
    if (last != (int)r) { last = (int)r; FZ(@"FckZck: HistorySyncCompanionService.isInitialSyncFinished -> %d", r); }
    return r;
}
static void (*orig_runWhen)(id, SEL, id);
static void new_runWhen(id self, SEL _cmd, id blk) {
    BOOL realFinished = NO;
    @try { realFinished = orig_isInit ? orig_isInit(self, sel_registerName("isInitialSyncFinished")) : NO; } @catch (NSException *e) {}
    FZ(@"FckZck 1.28.2: runWhenInitialSyncFinished called block=%@ realState=%d", blk ? @"yes" : @"nil", realFinished);
    // Preserve WhatsApp's original continuation semantics. Never execute it early.
    orig_runWhen(self, _cmd, blk);
}
static void (*orig_didUpdAB)(id, SEL);
static void new_didUpdAB(id self, SEL _cmd) {
    FZ(@"FckZck: HistorySyncCompanionService.didUpdateABProperties");
    orig_didUpdAB(self, _cmd);
}
static void (*orig_resumeBg)(id, SEL);
static void new_resumeBg(id self, SEL _cmd) {
    FZ(@"FckZck: HistorySyncCompanionService.resumeFromBackground");
    orig_resumeBg(self, _cmd);
}

// Observe the bootstrap critical block without changing WhatsApp state.
static void (*orig_hsSec)(id, SEL);
static void new_hsSec(id self, SEL _cmd) {
    FZ(@"FckZck: CompanionBootstrapLoading.handleSecurityNotificationSetting called");
    gSecCalled = YES;
    orig_hsSec(self, _cmd);
}

static void (*orig_critBlock)(id, SEL, id);
static void new_critBlock(id self, SEL _cmd, id arg) {
    FZ(@"FckZck 1.28.2: bootstrap critical block entered");
    orig_critBlock(self, _cmd, arg);
}


// WAAccountCleaner logout entry points. The timeout path in log 2 went through
// logoutAuthenticatedCompanionWithReason (".../normal/11").
static void (*orig_logoutAuth)(id, SEL, long long, BOOL, id);
static void new_logoutAuth(id self, SEL _cmd, long long reason, BOOL restart, id ctx) {
    FZ(@"FckZck: WAAccountCleaner.logoutAuthenticatedCompanion reason=%lld restart=%d", reason, restart);
    if (gBlockHistoryTimeoutLogout && reason == gBlockLogoutReason) {
        FZ(@"FckZck 1.28.2: -> history_sync_timeout logout blocked (no forced completion)");
        return;
    }
    orig_logoutAuth(self, _cmd, reason, restart, ctx);
}

static void (*orig_logoutComp)(id, SEL, long long, id, id);
static void new_logoutComp(id self, SEL _cmd, long long reason, id ctx, id completion) {
    FZ(@"FckZck: WAAccountCleaner.logoutCompanionWithReason reason=%lld", reason);
    orig_logoutComp(self, _cmd, reason, ctx, completion);
}

static BOOL gCleanerHooked = NO;
static BOOL gHistoryHooksDone = NO;
static BOOL FZInstallHistoryHooks(void) {
    if (gHistoryHooksDone) return YES;
    if (!gCleanerHooked) {
        Class cleaner = objc_getClass("WAAccountCleaner");
        if (cleaner) {
            FZHookIfPresent(cleaner, "logoutAuthenticatedCompanionWithReason:shouldRestartIfPossible:userContext:", "v36@0:8q16B24@28", (IMP)new_logoutAuth, (IMP *)&orig_logoutAuth);
            FZHookIfPresent(cleaner, "logoutCompanionWithReason:userContext:completion:", "v40@0:8q16@24@?32", (IMP)new_logoutComp, (IMP *)&orig_logoutComp);
            gCleanerHooked = YES;
        } else FZ(@"FckZck: WAAccountCleaner not found yet");
    }
    Class boot = objc_getClass("WACompanionRegistration.CompanionBootstrapLoading");
    if (!boot) boot = objc_getClass("_TtC23WACompanionRegistration25CompanionBootstrapLoading");
    Class ui = objc_getClass("WAHistorySync.HistorySyncCompanionUserInterfaceController");
    if (!ui) ui = objc_getClass("_TtC13WAHistorySync43HistorySyncCompanionUserInterfaceController");
    if (ui) FZHookIfPresent(ui, "currentSyncState", "q16@0:8", (IMP)new_syncState, (IMP *)&orig_syncState);
    else FZ(@"FckZck: HistorySyncCompanionUserInterfaceController not found");
    Class svc = objc_getClass("WAHistorySyncCompanionService");
    Class lgr = objc_getClass("WACompanionRegistrationLogger");
    if (!boot && !svc && !lgr) return NO;
    if (boot) {
        FZHookIfPresent(boot, "handleInitialHistorySync", "v16@0:8", (IMP)new_hsInitial, (IMP *)&orig_hsInitial);
        FZHookIfPresent(boot, "handleHistorySyncFailure:", "v24@0:8@16", (IMP)new_hsFailure, (IMP *)&orig_hsFailure);
        FZHookIfPresent(boot, "handleSyncdCriticalBlockCollection:", "v24@0:8@16", (IMP)new_critBlock, (IMP *)&orig_critBlock);
        FZHookIfPresent(boot, "handleSecurityNotificationSetting", "v16@0:8", (IMP)new_hsSec, (IMP *)&orig_hsSec);
    } else FZ(@"FckZck: CompanionBootstrapLoading not found");
    if (svc) {
        FZHookIfPresent(svc, "handleMessage:stanza:", "v32@0:8@16@24", (IMP)new_hsHandle, (IMP *)&orig_hsHandle);
        FZHookIfPresent(svc, "isInitialSyncFinished", "B16@0:8", (IMP)new_isInit, (IMP *)&orig_isInit);
        FZHookIfPresent(svc, "runWhenInitialSyncFinished:", "v24@0:8@?16", (IMP)new_runWhen, (IMP *)&orig_runWhen);
        FZHookIfPresent(svc, "didUpdateABProperties", "v16@0:8", (IMP)new_didUpdAB, (IMP *)&orig_didUpdAB);
        FZHookIfPresent(svc, "resumeFromBackground", "v16@0:8", (IMP)new_resumeBg, (IMP *)&orig_resumeBg);
    }
    else FZ(@"FckZck: WAHistorySyncCompanionService not found");
    if (lgr) FZHookIfPresent(lgr, "handlePreKeysUploadFail:", "v24@0:8@16", (IMP)new_preKeyFail, (IMP *)&orig_preKeyFail);
    FZInstallDiagnosticHistoryHooks();
    gHistoryHooksDone = YES;
    return YES;
}
// -------------------------------------------------------------------------

// ---- Signal store diagnostics + deprecated-session experiment (1.12) -------
// Log 2: the first two pkmsg from the primary were decrypted with sessions stored as
// "deprecated=1"; the next four looked for "deprecated=0", found no session, then failed
// with load_pre_key/missing (-1003). These hooks log every session/prekey access with the
// address's deprecated flag, and (optionally) force that flag to NO for individual sessions.
@protocol FZAddr <NSObject>
- (BOOL)isDeprecated;
@end

static NSString *FZAddr(id a) {
    if (!a) return @"nil";
    BOOL dep = NO;
    @try { dep = [(id<FZAddr>)a isDeprecated]; } @catch (NSException *e) {}
    return [NSString stringWithFormat:@"%@ dep=%d", FZMask([NSString stringWithFormat:@"%@", a]), dep];
}

static id (*orig_addrInit1)(id, SEL, id, id, BOOL);
static id new_addrInit1(id self, SEL _cmd, id jid, id gid, BOOL dep) {
    BOOL use = (gid == nil && gDeprecatedOverride >= 0) ? (gDeprecatedOverride != 0) : dep;
    if (dep != use) FZ(@"FckZck: SignalAddress(jid=%@ group=%@) deprecated %d -> %d", FZMask([NSString stringWithFormat:@"%@", jid]), gid ? @"yes" : @"no", dep, use);
    return orig_addrInit1(self, _cmd, jid, gid, use);
}

static id (*orig_addrInit2)(id, SEL, id, id, BOOL, id);
static id new_addrInit2(id self, SEL _cmd, id jid, id gcjid, BOOL dep, id acct) {
    BOOL use = (gcjid == nil && gDeprecatedOverride >= 0) ? (gDeprecatedOverride != 0) : dep;
    if (dep != use) FZ(@"FckZck: SignalAddress(jid=%@ groupCipher=%@) deprecated %d -> %d", FZMask([NSString stringWithFormat:@"%@", jid]), gcjid ? @"yes" : @"no", dep, use);
    return orig_addrInit2(self, _cmd, jid, gcjid, use, acct);
}

static BOOL (*orig_storeSess)(id, SEL, id, id);
static BOOL new_storeSess(id self, SEL _cmd, id rec, id addr) {
    BOOL r = orig_storeSess(self, _cmd, rec, addr);
    FZ(@"FckZck: KeyStore.storeSessionRecord addr=%@ -> %d", FZAddr(addr), r);
    return r;
}

static id (*orig_getSess)(id, SEL, id);
static id new_getSess(id self, SEL _cmd, id addr) {
    id r = orig_getSess(self, _cmd, addr);
    FZ(@"FckZck: KeyStore.sessionRecordForAddress addr=%@ -> %@", FZAddr(addr), r ? @"found" : @"MISSING");
    return r;
}

static BOOL (*orig_hasSess)(id, SEL, id);
static BOOL new_hasSess(id self, SEL _cmd, id addr) {
    BOOL r = orig_hasSess(self, _cmd, addr);
    FZ(@"FckZck: KeyStore.containsSessionForAddress addr=%@ -> %d", FZAddr(addr), r);
    return r;
}

static id (*orig_getPre)(id, SEL, int);
static BOOL gProbing = NO;
static id new_getPre(id self, SEL _cmd, int pid) {
    id r = orig_getPre(self, _cmd, pid);
    FZ(@"FckZck: KeyStore.fetchPreKeyRecordForId %d -> %@", pid, r ? @"found" : @"MISSING");
    // 1.16 diagnostic: on a miss, probe a few other ids to see WHICH one-time prekeys
    // exist locally (the server was given ids 1..200 at registration). Read-only.
    if (!r && !gProbing) {
        gProbing = YES;
        @try {
            int ids[] = {1, 2, 50, 99, 100, 102, 150, 199, 200, 201, 300, 500};
            NSMutableString *p = [NSMutableString string];
            for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
                id x = orig_getPre(self, _cmd, ids[i]);
                [p appendFormat:@" %d=%@", ids[i], x ? @"Y" : @"n"];
            }
            FZ(@"FckZck: prekey probe after miss of %d:%@", pid, p);
        } @catch (NSException *e) {}
        gProbing = NO;
    }
    return r;
}

static BOOL (*orig_rmPre)(id, SEL, int);
static BOOL new_rmPre(id self, SEL _cmd, int pid) {
    BOOL r = orig_rmPre(self, _cmd, pid);
    FZ(@"FckZck: KeyStore.removePreKeyRecordWithId %d -> %d", pid, r);
    return r;
}

static BOOL (*orig_storePre)(id, SEL, id, int);
static BOOL new_storePre(id self, SEL _cmd, id rec, int pid) {
    BOOL r = orig_storePre(self, _cmd, rec, pid);
    FZ(@"FckZck: KeyStore.storePreKeyRecord id=%d -> %d", pid, r);
    return r;
}

static NSMutableArray *gLidAddrs;       // @lid addresses that decrypted something OK
static NSMutableDictionary *gPnToLid;   // PN address description -> LID address (proven by a decrypt)

static NSString *FZAddrKey(id a) { return [NSString stringWithFormat:@"%@", a]; }
static BOOL FZIsLid(id a) { return a && [FZAddrKey(a) rangeOfString:@"@lid"].location != NSNotFound; }
static BOOL FZIsPn(id a)  { return a && [FZAddrKey(a) rangeOfString:@"@s.whatsapp.net"].location != NSNotFound; }

static void FZRememberLid(id addr) {
    if (!FZIsLid(addr) || !gLidAddrs) return;
    NSString *k = FZAddrKey(addr);
    @synchronized (gLidAddrs) {
        for (id a in gLidAddrs) { if ([FZAddrKey(a) isEqualToString:k]) return; }
        if (gLidAddrs.count < 8) {
            [gLidAddrs addObject:addr];
            FZ(@"FckZck: remembered LID address %@", FZMask(k));
        }
    }
}

// Candidates to retry a failed PN decrypt with: the proven mapping first, then every known LID.
static NSArray *FZLidCandidates(id pnAddr) {
    if (!gLidFallback || !gLidAddrs || !FZIsPn(pnAddr)) return nil;
    NSMutableArray *order = [NSMutableArray array];
    @synchronized (gLidAddrs) {
        id mapped = gPnToLid[FZAddrKey(pnAddr)];
        if (mapped) [order addObject:mapped];
        for (id c in gLidAddrs) { if (c != mapped) [order addObject:c]; }
    }
    return order;
}

static void FZRememberPair(id pnAddr, id lidAddr) {
    @synchronized (gLidAddrs) { gPnToLid[FZAddrKey(pnAddr)] = lidAddr; }
}

static int (*orig_decPre)(id, SEL, id, id, void *, BOOL);
static int new_decPre(id self, SEL _cmd, id data, id addr, void *out, BOOL stateless) {
    int r = orig_decPre(self, _cmd, data, addr, out, stateless);
    FZ(@"FckZck: Coordinator.decryptPreKeyCiphertext len=%lu addr=%@ stateless=%d -> %d",
       (unsigned long)[(NSData *)data length], FZAddr(addr), stateless, r);
    if (r == 0) { FZRememberLid(addr); return r; }
    for (id c in FZLidCandidates(addr)) {
        int r2 = orig_decPre(self, _cmd, data, c, out, stateless);
        FZ(@"FckZck: LID fallback (pkmsg) %@ via %@ -> %d", FZMask(FZAddrKey(addr)), FZMask(FZAddrKey(c)), r2);
        if (r2 == 0) { FZRememberPair(addr, c); return 0; }
    }
    return r;
}

static int (*orig_decReg)(id, SEL, id, id, void *);
static int new_decReg(id self, SEL _cmd, id data, id addr, void *out) {
    int r = orig_decReg(self, _cmd, data, addr, out);
    FZ(@"FckZck: Coordinator.decryptRegularCiphertext len=%lu addr=%@ -> %d",
       (unsigned long)[(NSData *)data length], FZAddr(addr), r);
    if (r == 0) { FZRememberLid(addr); return r; }
    for (id c in FZLidCandidates(addr)) {
        int r2 = orig_decReg(self, _cmd, data, c, out);
        FZ(@"FckZck: LID fallback (msg) %@ via %@ -> %d", FZMask(FZAddrKey(addr)), FZMask(FZAddrKey(c)), r2);
        if (r2 == 0) { FZRememberPair(addr, c); return 0; }
    }
    return r;
}

static BOOL gSignalHooked = NO;
static BOOL FZInstallSignalHooks(void) {
    if (gSignalHooked) return YES;
    if (!gLidAddrs) { gLidAddrs = [NSMutableArray array]; gPnToLid = [NSMutableDictionary dictionary]; }
    Class ad = objc_getClass("WASignalAddress");
    Class ks = objc_getClass("WASignalKeyStore");
    Class co = objc_getClass("WASignalCoordinator");
    if (!ad && !ks && !co) return NO;
    if (ad) {
        FZHookIfPresent(ad, "initWithDeviceJID:groupID:deprecated:", "@36@0:8@16@24B32", (IMP)new_addrInit1, (IMP *)&orig_addrInit1);
        FZHookIfPresent(ad, "initWithDeviceJID:groupCipherJID:deprecated:accountProvider:", "@44@0:8@16@24B32@36", (IMP)new_addrInit2, (IMP *)&orig_addrInit2);
    } else FZ(@"FckZck: WASignalAddress not found");
    if (ks) {
        FZHookIfPresent(ks, "storeSessionRecord:forAddress:", "B32@0:8@16@24", (IMP)new_storeSess, (IMP *)&orig_storeSess);
        FZHookIfPresent(ks, "sessionRecordForAddress:", "@24@0:8@16", (IMP)new_getSess, (IMP *)&orig_getSess);
        FZHookIfPresent(ks, "containsSessionForAddress:", "B24@0:8@16", (IMP)new_hasSess, (IMP *)&orig_hasSess);
        FZHookIfPresent(ks, "fetchPreKeyRecordForId:", "@20@0:8i16", (IMP)new_getPre, (IMP *)&orig_getPre);
        FZHookIfPresent(ks, "removePreKeyRecordWithId:", "B20@0:8i16", (IMP)new_rmPre, (IMP *)&orig_rmPre);
        FZHookIfPresent(ks, "storePreKeyRecord:id:", "B28@0:8@16i24", (IMP)new_storePre, (IMP *)&orig_storePre);
    } else FZ(@"FckZck: WASignalKeyStore not found");
    if (co) {
        FZHookIfPresent(co, "decryptPreKeyCiphertextData:forSignalAddress:plaintextData:statelessly:", "i44@0:8@16@24o^@32B40", (IMP)new_decPre, (IMP *)&orig_decPre);
        FZHookIfPresent(co, "decryptRegularCiphertextData:forSignalAddress:plaintextData:", "i40@0:8@16@24o^@32", (IMP)new_decReg, (IMP *)&orig_decReg);
    } else FZ(@"FckZck: WASignalCoordinator not found");
    gSignalHooked = YES;
    return YES;
}
// -------------------------------------------------------------------------

// ---- 1.28.1: DeviceProps (what the companion tells the PRIMARY PHONE) -------
// Log 2: classes WAPBDeviceProps* do not exist, and no pair-device stanza is used. So we find, at
// runtime, every class with a setter taking the DeviceProps bytes (setDeviceProps: etc.), and
// rewrite those bytes as raw protobuf: spoofed app version (field 2), requireFullSync (4) and a
// historySyncConfig (5). No class names needed. Unlink + link again after installing.
static BOOL FZPBVarint(const uint8_t *b, NSUInteger n, NSUInteger *i, uint64_t *out) {
    uint64_t v = 0; int sh = 0;
    while (*i < n && sh < 64) { uint8_t c = b[(*i)++]; v |= (uint64_t)(c & 0x7f) << sh; if (!(c & 0x80)) { *out = v; return YES; } sh += 7; }
    return NO;
}
static void FZPBPut(NSMutableData *d, uint64_t v) {
    do { uint8_t c = v & 0x7f; v >>= 7; if (v) c |= 0x80; [d appendBytes:&c length:1]; } while (v);
}
// fields: array of @{f, w, v(NSNumber|NSData)}
static NSMutableArray *FZPBParse(NSData *d) {
    NSMutableArray *out = [NSMutableArray array];
    const uint8_t *b = (const uint8_t *)d.bytes; NSUInteger n = d.length, i = 0;
    while (i < n) {
        uint64_t tag, v;
        if (!FZPBVarint(b, n, &i, &tag)) return nil;
        int w = tag & 7; uint64_t f = tag >> 3;
        if (f == 0) return nil;
        if (w == 0) { if (!FZPBVarint(b, n, &i, &v)) return nil; [out addObject:@{@"f":@(f), @"w":@0, @"v":@(v)}]; }
        else if (w == 2) { if (!FZPBVarint(b, n, &i, &v) || v > n - i) return nil; [out addObject:@{@"f":@(f), @"w":@2, @"v":[d subdataWithRange:NSMakeRange(i, (NSUInteger)v)]}]; i += (NSUInteger)v; }
        else if (w == 1) { if (n - i < 8) return nil; [out addObject:@{@"f":@(f), @"w":@1, @"v":[d subdataWithRange:NSMakeRange(i, 8)]}]; i += 8; }
        else if (w == 5) { if (n - i < 4) return nil; [out addObject:@{@"f":@(f), @"w":@5, @"v":[d subdataWithRange:NSMakeRange(i, 4)]}]; i += 4; }
        else return nil;
    }
    return out;
}
static NSData *FZPBSerialize(NSArray *fields) {
    NSMutableData *o = [NSMutableData data];
    for (NSDictionary *e in fields) {
        int w = [e[@"w"] intValue];
        FZPBPut(o, ([e[@"f"] unsignedLongLongValue] << 3) | w);
        if (w == 0) FZPBPut(o, [e[@"v"] unsignedLongLongValue]);
        else if (w == 2) { NSData *x = e[@"v"]; FZPBPut(o, x.length); [o appendData:x]; }
        else [o appendData:e[@"v"]];
    }
    return o;
}
static NSData *FZPBGet(NSArray *fields, uint64_t f) {
    for (NSDictionary *e in fields) if ([e[@"f"] unsignedLongLongValue] == f && [e[@"w"] intValue] == 2) return e[@"v"];
    return nil;
}
static void FZPBSet(NSMutableArray *fields, uint64_t f, int w, id v) {
    for (NSUInteger k = 0; k < fields.count; k++) if ([fields[k][@"f"] unsignedLongLongValue] == f) { [fields removeObjectAtIndex:k]; k--; }
    [fields addObject:@{@"f":@(f), @"w":@(w), @"v":v}];
}
static NSData *FZTuneDevicePropsData(NSData *in) {
    @try {
        NSMutableArray *f = FZPBParse(in);
        if (!f || !f.count || (!FZPBGet(f, 2) && !FZPBGet(f, 1))) { FZ(@"FckZck 1.27: bytes (%lu) do not look like DeviceProps, untouched", (unsigned long)in.length); return in; }
        NSMutableArray *ver = FZPBGet(f, 2) ? FZPBParse(FZPBGet(f, 2)) : [NSMutableArray array];
        if (!ver) ver = [NSMutableArray array];
        for (int i = 0; i < 4; i++) FZPBSet(ver, i + 1, 0, @(gNum[i]));
        FZPBSet(f, 2, 2, FZPBSerialize(ver));
        FZPBSet(f, 4, 0, @(gReqFullSync ? 1 : 0));
        NSMutableArray *cfg = FZPBGet(f, 5) ? FZPBParse(FZPBGet(f, 5)) : [NSMutableArray array];
        if (!cfg) cfg = [NSMutableArray array];
        FZPBSet(cfg, 1, 0, @(gHistDays));     // fullSyncDaysLimit
        FZPBSet(cfg, 2, 0, @(1024));          // fullSyncSizeMbLimit
        FZPBSet(cfg, 3, 0, @(10240));         // storageQuotaMb
        FZPBSet(cfg, 5, 0, @(gHistDays));     // recentSyncDaysLimit
        FZPBSet(f, 5, 2, FZPBSerialize(cfg));
        NSData *out = FZPBSerialize(f);
        static int hexN = 0;
        if (hexN++ < 3) {
            NSMutableString *h1 = [NSMutableString string], *h2 = [NSMutableString string];
            for (NSUInteger i = 0; i < in.length && i < 96; i++) [h1 appendFormat:@"%02x", ((const uint8_t *)in.bytes)[i]];
            for (NSUInteger i = 0; i < out.length && i < 96; i++) [h2 appendFormat:@"%02x", ((const uint8_t *)out.bytes)[i]];
            FZ(@"FckZck 1.27: DeviceProps hex in=%@ out=%@", h1, h2);
        }
        FZ(@"FckZck 1.27: DeviceProps rewritten %lu -> %lu bytes (version %@, fullSync=%d, days=%d)", (unsigned long)in.length, (unsigned long)out.length, gVersion, gReqFullSync, gHistDays);
        return out;
    } @catch (NSException *e) { FZ(@"FckZck 1.27: DeviceProps rewrite exception %@", e); return in; }
}

static void FZHookPropsSetter(Class c, SEL sel) {
    __block IMP orig = NULL;
    IMP repl = imp_implementationWithBlock(^(id self, id v) {
        id nv = v;
        if ([v isKindOfClass:[NSData class]]) nv = FZTuneDevicePropsData((NSData *)v);
        else FZ(@"FckZck 1.27: %s %s got %@ (not NSData), untouched", class_getName([self class]), sel_getName(sel), v ? NSStringFromClass([v class]) : @"nil");
        ((void (*)(id, SEL, id))orig)(self, sel, nv);
    });
    MSHookMessageEx(c, sel, repl, &orig);
    FZ(@"FckZck 1.27: hooked %s %s", class_getName(c), sel_getName(sel));
}

// ---- 1.27.2: hook the CompanionProps model classes themselves ---------------
// Log 3: setCompanionProps: on the RegData/DeviceInfo classes never fired (props are not set
// through them while pairing). The classes WAPBCompanionProps / _AppVersion / _HistorySyncConfig
// do exist, so we hook their setters and getters too.
static BOOL FZHookB(Class c, const char *sel, const char *types, IMP (^mk)(IMP *slot, SEL s)) {
    SEL s = sel_registerName(sel);
    Method m = class_getInstanceMethod(c, s);
    if (!m) { FZ(@"FckZck 1.27: %s has no %s", class_getName(c), sel); return NO; }
    const char *e = method_getTypeEncoding(m);
    const char *p = e ? strstr(e, "@0:8") : NULL;
    if (!p || (types[0] && (!p[4] || !strchr(types, p[4])))) { FZ(@"FckZck 1.27: %s %s unexpected type %s", class_getName(c), sel, e ? e : "?"); return NO; }
    IMP *slot = (IMP *)calloc(1, sizeof(IMP));
    MSHookMessageEx(c, s, mk(slot, s), slot);
    FZ(@"FckZck 1.27: hooked %s %s (%s)", class_getName(c), sel, e);
    return YES;
}
static void FZSetKV(id o, NSString *k, id v) {
    @try { [o setValue:v forKey:k]; FZ(@"FckZck 1.27: %@=%@ (now %@)", k, v, [o valueForKey:k]); }
    @catch (NSException *e) { FZ(@"FckZck 1.27: cannot set %@: %@", k, e.reason); }
}
static void FZTuneProps(id p) {
    static BOOL busy = NO;
    if (busy || !p) return;
    busy = YES;
    @try {
        id cfg = nil;
        @try { cfg = [p valueForKey:@"historySyncConfig"]; } @catch (NSException *e) { cfg = nil; }
        Class cc = objc_getClass("WAPBCompanionProps_HistorySyncConfig");
        if (!cfg && cc) { cfg = [[cc alloc] init]; FZSetKV(p, @"historySyncConfig", cfg); }
        FZSetKV(p, @"requireFullSync", @(gReqFullSync));
        if (cfg) {
            FZSetKV(cfg, @"fullSyncDaysLimit", @(gHistDays));
            FZSetKV(cfg, @"recentSyncDaysLimit", @(gHistDays));
            FZSetKV(cfg, @"fullSyncSizeMbLimit", @(1024));
            FZSetKV(cfg, @"storageQuotaMb", @(10240));
        } else FZ(@"FckZck 1.27: no historySyncConfig object");
    } @catch (NSException *e) { FZ(@"FckZck 1.27: tune exception %@", e); }
    busy = NO;
}
static void FZListSel(const char *cn) {
    Class c = objc_getClass(cn);
    if (!c) return;
    unsigned int n = 0; Method *ms = class_copyMethodList(c, &n);
    NSMutableArray *a = [NSMutableArray array];
    for (unsigned int i = 0; i < n; i++) { const char *x = sel_getName(method_getName(ms[i])); if (x[0] != '.') [a addObject:@(x)]; }
    free(ms);
    FZ(@"FckZck 1.27: methods of %s: %@", cn, [a componentsJoinedByString:@" "]);
}
static BOOL gCompHooked = NO;
static void FZInstallCompanionHooks(void) {
    if (gCompHooked) return;
    Class av = objc_getClass("WAPBCompanionProps_AppVersion");
    Class cp = objc_getClass("WAPBCompanionProps");
    if (!av || !cp) return;
    gCompHooked = YES;
    FZListSel("WAPBCompanionProps"); FZListSel("WAPBCompanionProps_HistorySyncConfig");
    FZListSel("WAPBClientPayload_CompanionRegData"); FZListSel("WAPBCompanionDeviceInfo");
    const char *names[] = {"setPrimary:", "setSecondary:", "setTertiary:", "setQuaternary:"};
    for (int i = 0; i < 4; i++) {
        int idx = i;
        FZHookB(av, names[i], "Ii", ^IMP(IMP *slot, SEL s) {
            return imp_implementationWithBlock(^(id self, unsigned int v) {
                ((void (*)(id, SEL, unsigned int))*slot)(self, s, (unsigned int)gNum[idx]);
            });
        });
    }
    FZHookB(cp, "setRequireFullSync:", "B", ^IMP(IMP *slot, SEL s) {
        return imp_implementationWithBlock(^(id self, BOOL v) {
            ((void (*)(id, SEL, BOOL))*slot)(self, s, (BOOL)gReqFullSync);
        });
    });
    FZHookB(cp, "setPlatformType:", "Ii", ^IMP(IMP *slot, SEL s) {
        return imp_implementationWithBlock(^(id self, unsigned int v) {
            ((void (*)(id, SEL, unsigned int))*slot)(self, s, v);
            FZ(@"FckZck 1.27: CompanionProps.setPlatformType(%u)", v);
            FZTuneProps(self);
        });
    });
    FZHookB(cp, "setHistorySyncConfig:", "@", ^IMP(IMP *slot, SEL s) {
        return imp_implementationWithBlock(^(id self, id v) {
            ((void (*)(id, SEL, id))*slot)(self, s, v);
            FZTuneProps(self);
        });
    });
    FZHookB(cp, "setVersion:", "@", ^IMP(IMP *slot, SEL s) {
        return imp_implementationWithBlock(^(id self, id v) {
            ((void (*)(id, SEL, id))*slot)(self, s, v);
            FZTuneProps(self);
        });
    });
    // Getter fallback: whoever reads the NSData gets the rewritten bytes.
    const char *cls[] = {"WAPBClientPayload_CompanionRegData", "WAPBCompanionDeviceInfo"};
    for (int i = 0; i < 2; i++) {
        Class c = objc_getClass(cls[i]);
        if (!c) continue;
        FZHookB(c, "companionProps", "", ^IMP(IMP *slot, SEL s) {
            return imp_implementationWithBlock(^id(id self) {
                id r = ((id (*)(id, SEL))*slot)(self, s);
                FZ(@"FckZck 1.27: %s.companionProps read (%@)", class_getName([self class]), r ? NSStringFromClass([r class]) : @"nil");
                if ([r isKindOfClass:[NSData class]]) return FZTuneDevicePropsData((NSData *)r);
                return r;
            });
        });
    }
}

// ---- 1.27.3: rewrite the CompanionProps bytes inside the ClientPayload right before it is
// serialized (they are not built through setters in this run: persisted/parsed instead).
static NSString *gRegKey = nil;
static void FZTunePayload(id payload) {
    @try {
        if (!gRegKey) return;
        id reg = [payload valueForKey:gRegKey];
        if (!reg) return;
        id p = [reg valueForKey:@"companionProps"];
        if (![p isKindOfClass:[NSData class]] || ![(NSData *)p length]) { FZ(@"FckZck 1.27: payload companionProps empty/not data (%@)", p ? NSStringFromClass([p class]) : @"nil"); return; }
        NSData *n = FZTuneDevicePropsData((NSData *)p);
        if (![n isEqualToData:(NSData *)p]) { [reg setValue:n forKey:@"companionProps"]; FZ(@"FckZck 1.27: payload companionProps replaced"); }
    } @catch (NSException *e) { FZ(@"FckZck 1.27: payload tune exception %@", e); }
}
static BOOL gPayloadHooked = NO;
static void FZInstallPayloadHook(void) {
    if (gPayloadHooked) return;
    Class pc = objc_getClass("WAPBClientPayload");
    Class rc = objc_getClass("WAPBClientPayload_CompanionRegData");
    if (!pc || !rc) return;
    gPayloadHooked = YES;
    unsigned int n = 0;
    objc_property_t *ps = class_copyPropertyList(pc, &n);
    NSMutableArray *names = [NSMutableArray array];
    for (unsigned int i = 0; i < n; i++) {
        const char *nm = property_getName(ps[i]);
        const char *at = property_getAttributes(ps[i]);
        if (nm) [names addObject:@(nm)];
        if (nm && at && strstr(at, "WAPBClientPayload_CompanionRegData")) gRegKey = @(nm);
    }
    free(ps);
    FZ(@"FckZck 1.27: ClientPayload props: %@ | regData key=%@", [names componentsJoinedByString:@" "], gRegKey);
    FZHookB(pc, "data", "", ^IMP(IMP *slot, SEL s) {
        return imp_implementationWithBlock(^id(id self) {
            FZ(@"FckZck 1.27: ClientPayload.data called");
            FZTunePayload(self);
            return ((id (*)(id, SEL))*slot)(self, s);
        });
    });
}

// ---- 1.27.4: trace + early rewrite at the GPBMessage serialization entry points ------
// Log 5: ClientPayload.data / companionProps setters/getters never fired while registering
// ("register_as_companion_phone"), so the payload is serialized through another GPB path.
// Hook the base GPBMessage methods; trace WAPBClientPayload*/WAPBCompanion* and rewrite the
// props in serializedSize (the first call of every serialization path).
static int gTraceN = 0;
static BOOL FZTraced(id self, BOOL *isPayload) {
    const char *cn = object_getClassName(self);
    if (!cn) return NO;
    *isPayload = (strcmp(cn, "WAPBClientPayload") == 0);
    return *isPayload || strncmp(cn, "WAPBClientPayload_", 18) == 0 || strncmp(cn, "WAPBCompanion", 13) == 0;
}
static BOOL gTraceHooked = NO;
static void FZInstallTraceHooks(void) {
    if (gTraceHooked) return;
    Class g = objc_getClass("GPBMessage");
    if (!g) return;
    gTraceHooked = YES;
    FZHookB(g, "serializedSize", "", ^IMP(IMP *slot, SEL s) {
        return imp_implementationWithBlock(^unsigned long(id self) {
            BOOL pl = NO;
            if (FZTraced(self, &pl)) {
                if (gTraceN++ < 60) FZ(@"FckZck 1.27: trace serializedSize %s", object_getClassName(self));
                if (pl) FZTunePayload(self);
            }
            return ((unsigned long (*)(id, SEL))*slot)(self, s);
        });
    });
    FZHookB(g, "data", "", ^IMP(IMP *slot, SEL s) {
        return imp_implementationWithBlock(^id(id self) {
            BOOL pl = NO;
            if (FZTraced(self, &pl) && gTraceN++ < 60) FZ(@"FckZck 1.27: trace data %s", object_getClassName(self));
            return ((id (*)(id, SEL))*slot)(self, s);
        });
    });
    FZHookB(g, "writeToCodedOutputStream:", "@", ^IMP(IMP *slot, SEL s) {
        return imp_implementationWithBlock(^(id self, id st) {
            BOOL pl = NO;
            if (FZTraced(self, &pl) && gTraceN++ < 60) FZ(@"FckZck 1.27: trace writeToCodedOutputStream %s", object_getClassName(self));
            ((void (*)(id, SEL, id))*slot)(self, s, st);
        });
    });
    FZHookB(g, "writeToOutputStream:", "@", ^IMP(IMP *slot, SEL s) {
        return imp_implementationWithBlock(^(id self, id st) {
            BOOL pl = NO;
            if (FZTraced(self, &pl)) {
                if (gTraceN++ < 60) FZ(@"FckZck 1.27: trace writeToOutputStream %s", object_getClassName(self));
                if (pl) FZTunePayload(self);
            }
            ((void (*)(id, SEL, id))*slot)(self, s, st);
        });
    });
    FZHookB(g, "delimitedData", "", ^IMP(IMP *slot, SEL s) {
        return imp_implementationWithBlock(^id(id self) {
            BOOL pl = NO;
            if (FZTraced(self, &pl) && gTraceN++ < 60) FZ(@"FckZck 1.27: trace delimitedData %s", object_getClassName(self));
            return ((id (*)(id, SEL))*slot)(self, s);
        });
    });
}

// ---- 1.28: hook the exported SharedModules payload builder (WACreateClientPayload) ------
// Log 6 stack: the ClientPayload is built by the C function WACreateClientPayload in SharedModules
// (called from _WCCConnectionDefaultDoConnectWithAuthKeys), not through GPBMessage serialization.
// We hook it by name; the return value is validated before touching it. If it is serialized
// ClientPayload bytes (NSData), field 19 (devicePairingData) -> field 8 (companionProps / DeviceProps)
// is rewritten with the spoofed version + full-history request.
static int FZCmpU(const void *a, const void *b) { uintptr_t x = *(const uintptr_t *)a, y = *(const uintptr_t *)b; return x < y ? -1 : (x > y); }
static BOOL FZIsObjC(void *r) {
    uintptr_t v = (uintptr_t)r;
    if (v < 0x100000000ULL || (v & 7) || (v >> 40)) return NO;
    if (malloc_size(r) < 16) return NO;
    uintptr_t cls = (*(uintptr_t *)r) & 0x0000000ffffffff8ULL;
    unsigned int n = 0;
    Class *cl = objc_copyClassList(&n);
    uintptr_t *arr = (uintptr_t *)malloc(sizeof(uintptr_t) * (n ? n : 1));
    for (unsigned int i = 0; i < n; i++) arr[i] = (uintptr_t)cl[i];
    free(cl);
    qsort(arr, n, sizeof(uintptr_t), FZCmpU);
    BOOL ok = bsearch(&cls, arr, n, sizeof(uintptr_t), FZCmpU) != NULL;
    free(arr);
    return ok;
}

static NSData *FZTuneClientPayloadBytes(NSData *in) {
    @try {
        NSMutableArray *f = FZPBParse(in);
        if (!f) { FZ(@"FckZck 1.28: payload bytes (%lu) are not protobuf, untouched", (unsigned long)in.length); return in; }
        NSData *reg = FZPBGet(f, 19);
        FZ(@"FckZck 1.28: ClientPayload %lu bytes, %lu fields, devicePairingData(19) %@", (unsigned long)in.length, (unsigned long)f.count, reg ? @"present" : @"absent");
        if (!reg) return in;
        NSMutableArray *sub = FZPBParse(reg);
        if (!sub) return in;
        uint64_t fid = 8;
        NSData *props = FZPBGet(sub, 8);
        if (!props) {
            for (NSDictionary *e in sub) {   // fallback: any length-delimited field that parses like DeviceProps
                if ([e[@"w"] intValue] != 2) continue;
                NSMutableArray *t = FZPBParse(e[@"v"]);
                if (t && FZPBGet(t, 2) && FZPBGet(t, 1)) { props = e[@"v"]; fid = [e[@"f"] unsignedLongLongValue]; break; }
            }
        }
        if (!props) { FZ(@"FckZck 1.28: no companionProps inside devicePairingData"); return in; }
        NSData *np = FZTuneDevicePropsData(props);
        if ([np isEqualToData:props]) return in;
        FZPBSet(sub, fid, 2, np);
        FZPBSet(f, 19, 2, FZPBSerialize(sub));
        NSData *out = FZPBSerialize(f);
        FZ(@"FckZck 1.28: ClientPayload rewritten %lu -> %lu bytes", (unsigned long)in.length, (unsigned long)out.length);
        return out;
    } @catch (NSException *e) { FZ(@"FckZck 1.28: payload rewrite exception %@", e); return in; }
}

static void *FZHandlePayloadResult(void *r, const char *tag) {
    if (!FZIsObjC(r)) { FZ(@"FckZck 1.28: %s returned %p (not an ObjC object), untouched", tag, r); return r; }
    id o = (__bridge id)r;
    FZ(@"FckZck 1.28: %s returned %s", tag, object_getClassName(o));
    @try {
        if ([o isKindOfClass:[NSData class]]) {
            NSData *d = (NSData *)o;
            NSData *n = FZTuneClientPayloadBytes(d);
            if (n && ![n isEqualToData:d]) {
                if ([o isKindOfClass:[NSMutableData class]]) { [(NSMutableData *)o setData:n]; FZ(@"FckZck 1.28: payload patched in place"); }
                else { FZ(@"FckZck 1.28: payload replaced"); return (void *)CFBridgingRetain([NSData dataWithData:n]); }  // original leaked on purpose (ownership unknown)
            }
        } else if ([o isKindOfClass:objc_getClass("WAPBClientPayload")]) {
            FZTunePayload(o);
        }
    } @catch (NSException *e) { FZ(@"FckZck 1.28: handle exception %@", e); }
    return r;
}

typedef void *(*FZFn8)(void *, void *, void *, void *, void *, void *, void *, void *);
#define FZ_PAYFN(N) \
static FZFn8 orig_pf##N; \
static void *new_pf##N(void *a, void *b, void *c, void *d, void *e, void *f, void *g, void *h) { \
    void *r = orig_pf##N(a, b, c, d, e, f, g, h); \
    return FZHandlePayloadResult(r, "payloadFn" #N); }
FZ_PAYFN(0) FZ_PAYFN(1) FZ_PAYFN(2)

static NSArray *FZSymbols(const struct mach_header_64 *mh) {
    intptr_t slide = 0;
    for (uint32_t i = 0; i < _dyld_image_count(); i++)
        if ((const void *)_dyld_get_image_header(i) == (const void *)mh) { slide = _dyld_get_image_vmaddr_slide(i); break; }
    const uint8_t *p = (const uint8_t *)(mh + 1);
    struct symtab_command *st = NULL; struct segment_command_64 *le = NULL;
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        struct load_command *lc = (struct load_command *)p;
        if (lc->cmd == LC_SYMTAB) st = (struct symtab_command *)lc;
        else if (lc->cmd == LC_SEGMENT_64) { struct segment_command_64 *sc = (struct segment_command_64 *)lc; if (strcmp(sc->segname, "__LINKEDIT") == 0) le = sc; }
        p += lc->cmdsize;
    }
    NSMutableArray *out = [NSMutableArray array];
    if (!st || !le) return out;
    uintptr_t base = (uintptr_t)le->vmaddr + slide - le->fileoff;
    struct nlist_64 *nl = (struct nlist_64 *)(base + st->symoff);
    const char *str = (const char *)(base + st->stroff);
    for (uint32_t i = 0; i < st->nsyms; i++) {
        if ((nl[i].n_type & N_TYPE) != N_SECT) continue;
        const char *nm = str + nl[i].n_un.n_strx;
        if (nm[0]) [out addObject:@(nm)];
    }
    return out;
}

static void FZInstallPayloadFnHooks(MSImageRef image) {
    NSArray *syms = FZSymbols((const struct mach_header_64 *)image);
    FZ(@"FckZck 1.28: SharedModules exports %lu symbols", (unsigned long)syms.count);
    NSMutableArray *cand = [NSMutableArray array];
    int logged = 0;
    for (NSString *n in syms) {
        NSString *l = [n lowercaseString];
        if (logged < 120 && ([l containsString:@"payload"] || [l containsString:@"companion"] || [l containsString:@"deviceprops"] || [l containsString:@"regdata"] || [l containsString:@"noise"] || [l containsString:@"handshake"])) { FZ(@"FckZck 1.28: sym %@", n); logged++; }
        if ([n hasPrefix:@"_WACreate"] && [l containsString:@"payload"] && ![cand containsObject:n]) [cand addObject:n];
    }
    int k = 0;
    for (NSString *n in cand) {
        if (k >= 3) break;
        const char *c = [n UTF8String];
        void *sym = MSFindSymbol(image, c);
        if (!sym) continue;
        if (k == 0) MSHookFunction(sym, (void *)new_pf0, (void **)&orig_pf0);
        else if (k == 1) MSHookFunction(sym, (void *)new_pf1, (void **)&orig_pf1);
        else MSHookFunction(sym, (void *)new_pf2, (void **)&orig_pf2);
        FZ(@"FckZck 1.28: hooked payload builder %s as payloadFn%d", c, k);
        k++;
    }
    if (!k) FZ(@"FckZck 1.28: no WACreate*Payload* export found");
}

static int gPropsHooks = 0;
static NSMutableSet *gPropsSeen;
static void FZScanDeviceProps(void) {
    if (!gPropsSeen) gPropsSeen = [NSMutableSet set];
    const char *sels[] = {"setDeviceProps:", "setCompanionProps:", "setDevicePropsData:", "setClientProps:"};
    unsigned int n = 0;
    Class *cl = objc_copyClassList(&n);
    int logged = 0;
    for (unsigned int i = 0; i < n; i++) {
        const char *cn = class_getName(cl[i]);
        if (!cn) continue;
        if (logged < 40 && (strstr(cn, "DeviceProps") || strstr(cn, "CompanionProps") || strstr(cn, "HistorySyncConfig")) && ![gPropsSeen containsObject:@(cn)]) {
            [gPropsSeen addObject:@(cn)]; logged++;
            FZ(@"FckZck 1.27: found class %s", cn);
        }
        for (int k = 0; k < 4; k++) {
            SEL s = sel_registerName(sels[k]);
            Method m = class_getInstanceMethod(cl[i], s);
            if (!m) continue;
            NSString *key = [NSString stringWithFormat:@"%s.%s", cn, sels[k]];
            if ([gPropsSeen containsObject:key]) continue;
            [gPropsSeen addObject:key];
            const char *enc = method_getTypeEncoding(m);
            FZ(@"FckZck 1.27: candidate %s %s enc=%s", cn, sels[k], enc ? enc : "?");
            if (enc && strncmp(enc, "v24@0:8@16", 10) == 0) { FZHookPropsSetter(cl[i], s); gPropsHooks++; }
        }
    }
    free(cl);
}
static void FZScanLoop(int left) {
    FZScanDeviceProps();
    FZInstallCompanionHooks();
    FZInstallPayloadHook();
    FZInstallTraceHooks();
    if (left > 0) dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(4 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{ FZScanLoop(left - 1); });
    else FZ(@"FckZck 1.27: scan finished, hooks=%d", gPropsHooks);
}
// -------------------------------------------------------------------------

%ctor {
    FZLoadConfig();
    FZ(@"FckZck 1.28 compatibility build loaded in %@", [[NSBundle mainBundle] bundleIdentifier]);
    if (!FZInstallUserAgentHooks()) {
        FZ(@"FckZck: WAPBClientPayload_UserAgent not found yet, retrying in 3s");
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            if (!FZInstallUserAgentHooks()) FZ(@"FckZck: WAPBClientPayload_UserAgent still not found");
        });
    }
    // 1.18: one-off dump of the history-sync / bootstrap classes (names, selectors, type encodings)
    // -> <app Documents>/fckzck-history-classes.txt (written ~20 s after launch)
    FZDumpClassesMatching(@[@"HistorySync", @"InitialSync", @"InlinePayload", @"WAHistory", @"Bootstrap", @"CompanionSync"],
                          @"fckzck-history-classes.txt");
    if (!FZInstallSignalHooks()) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            if (!FZInstallSignalHooks()) FZ(@"FckZck: signal classes still not found");
        });
    }
    if (!FZInstallHistoryHooks()) {
        FZ(@"FckZck: history-sync classes not found yet, retrying in 3s and 10s");
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            if (!FZInstallHistoryHooks()) {
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(7 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                    if (!FZInstallHistoryHooks()) FZ(@"FckZck: history-sync classes still not found");
                });
            }
        });
    }
    FZScanLoop(45);
    FZDumpClassesMatching(@[@"CompanionProps", @"CompanionRegData", @"CompanionDeviceInfo"], @"fckzck-companion-classes.txt");
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
    FZInstallPayloadFnHooks(image);
}

%hook WALogWriter

-(NSString*)formatLogText:(NSString*)ar1 withLevel:(int)ar2 {
	NSString *result = %orig;
	static NSArray *keys;
	static dispatch_once_t once;
	dispatch_once(&once, ^{
		keys = @[@"md/", @"pair", @"link", @"companion", @"gcm", @"xmpp//", @"stream//", @"LL_E", @"LL_W", @"login", @"auth", @"deprecat", @"expire", @"version", @"signal", @"prekey", @"history-sync", @"logout"];
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
