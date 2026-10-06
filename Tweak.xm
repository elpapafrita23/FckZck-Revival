#import <Foundation/Foundation.h>
#include <substrate.h>
#import <CommonCrypto/CommonDigest.h>
#import <objc/runtime.h>

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
static NSString *gHistoryMode = @"continue";
static NSNumber *gForceSyncState = nil;
// Experiment (1.11): the app logs itself out ~120 s after pairing because history sync never
// completes (reason "history_sync_timeout"). When ON, that single logout is swallowed and the
// bootstrap is told the initial history sync finished instead.
// Config keys: blockHistoryTimeoutLogout (bool, default ON),
//              historyTimeoutRemovalReason (integer, default 11 = value seen in log 2).
static BOOL gBlockHistoryTimeoutLogout = NO;  // 1.12: OFF. Log 3 showed it only leaves an endless spinner (server rejects the device with 401 on relaunch)
// Experiment (1.12): force WASignalAddress "deprecated" for individual (non-group) sessions.
// -1 = leave as is, 0 = force NO (default), 1 = force YES. Config key: signalDeprecatedOverride (integer).
static int gDeprecatedOverride = 0;
// Experiment (1.13): if the bootstrap ("loading your chats") has not been told that the initial
// history sync finished N seconds after pairing, tell it ourselves. 0 = off.
// Config key: forceFinishBootstrapSeconds (integer).
static int gForceFinishSeconds = 40;
static BOOL gInitialCalled = NO;
static BOOL gSecCalled = NO;
static __weak id gHistSvc = nil;
static BOOL gForceScheduled = NO;
static long long gBlockLogoutReason = 11;
static __weak id gBootObj = nil;
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
    id bl = cfg[@"blockHistoryTimeoutLogout"];
    if ([bl respondsToSelector:@selector(boolValue)]) gBlockHistoryTimeoutLogout = [bl boolValue];
    id br = cfg[@"historyTimeoutRemovalReason"];
    if ([br isKindOfClass:[NSNumber class]]) gBlockLogoutReason = [br longLongValue];
    FZ(@"FckZck: blockHistoryTimeoutLogout=%d reason=%lld", gBlockHistoryTimeoutLogout, gBlockLogoutReason);
    id ff = cfg[@"forceFinishBootstrapSeconds"];
    if ([ff isKindOfClass:[NSNumber class]]) gForceFinishSeconds = [ff intValue];
    FZ(@"FckZck: forceFinishBootstrapSeconds=%d", gForceFinishSeconds);
    id so = cfg[@"signalDeprecatedOverride"];
    if ([so isKindOfClass:[NSNumber class]]) gDeprecatedOverride = [so intValue];
    FZ(@"FckZck: signalDeprecatedOverride=%d", gDeprecatedOverride);
    id hm = cfg[@"historySyncFailureMode"];
    if ([hm isKindOfClass:[NSString class]] && [(NSString *)hm length]) gHistoryMode = hm;
    FZ(@"FckZck: historySyncFailureMode=%@", gHistoryMode);
    id fs = cfg[@"forceSyncState"];
    if ([fs isKindOfClass:[NSNumber class]]) { gForceSyncState = fs; FZ(@"FckZck: forceSyncState=%@", fs); }
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
    FZ(@"FckZck: HistorySyncCompanionService.runWhenInitialSyncFinished: called (block=%@)", blk ? @"yes" : @"nil");
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

// CompanionBootstrapLoading waits for several steps. Log 6 showed criticalBlock, criticalUnblockLow
// and (forced) initialSync, but never handleSecurityNotificationSetting -- the primary normally
// delivers that through history sync, which never gets processed here.
static void (*orig_hsSec)(id, SEL);
static void new_hsSec(id self, SEL _cmd) {
    FZ(@"FckZck: CompanionBootstrapLoading.handleSecurityNotificationSetting called");
    gSecCalled = YES;
    orig_hsSec(self, _cmd);
}

static void (*orig_critBlock)(id, SEL, id);
static void new_critBlock(id self, SEL _cmd, id arg) {
    gBootObj = self;
    if (gForceFinishSeconds > 0 && !gForceScheduled) {
        gForceScheduled = YES;
        FZ(@"FckZck: bootstrap object captured, will force-finish in %d s if still loading", gForceFinishSeconds);
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)gForceFinishSeconds * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
            id boot = gBootObj;
            if (gInitialCalled && gSecCalled) { FZ(@"FckZck: force-finish not needed, bootstrap steps already reported"); return; }
            if (boot && orig_hsInitial) {
                id svc = gHistSvc;
                FZ(@"FckZck: force-finish: service=%@ isInitialSyncFinished(before)=%d", svc ? @"yes" : @"nil", svc ? (int)[(id<FZSvc>)svc isInitialSyncFinished] : -1);
                if (!gInitialCalled) {
                    FZ(@"FckZck: force-finish: calling handleInitialHistorySync");
                    gInitialCalled = YES;
                    orig_hsInitial(boot, sel_registerName("handleInitialHistorySync"));
                }
                if (!gSecCalled && orig_hsSec) {
                    FZ(@"FckZck: force-finish: calling handleSecurityNotificationSetting");
                    gSecCalled = YES;
                    orig_hsSec(boot, sel_registerName("handleSecurityNotificationSetting"));
                }
                if (svc) FZ(@"FckZck: force-finish: isInitialSyncFinished(after)=%d", (int)[(id<FZSvc>)svc isInitialSyncFinished]);
            } else FZ(@"FckZck: force-finish: no bootstrap object");
        });
    }
    orig_critBlock(self, _cmd, arg);
}

// WAAccountCleaner logout entry points. The timeout path in log 2 went through
// logoutAuthenticatedCompanionWithReason (".../normal/11").
static void (*orig_logoutAuth)(id, SEL, long long, BOOL, id);
static void new_logoutAuth(id self, SEL _cmd, long long reason, BOOL restart, id ctx) {
    FZ(@"FckZck: WAAccountCleaner.logoutAuthenticatedCompanion reason=%lld restart=%d", reason, restart);
    if (gBlockHistoryTimeoutLogout && reason == gBlockLogoutReason) {
        id boot = gBootObj;
        if (boot && orig_hsInitial) {
            FZ(@"FckZck: -> logout blocked, telling bootstrap the initial history sync finished");
            orig_hsInitial(boot, sel_registerName("handleInitialHistorySync"));
        } else {
            FZ(@"FckZck: -> logout blocked (no bootstrap object captured, nothing else to do)");
        }
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
static id new_getPre(id self, SEL _cmd, int pid) {
    id r = orig_getPre(self, _cmd, pid);
    FZ(@"FckZck: KeyStore.fetchPreKeyRecordForId %d -> %@", pid, r ? @"found" : @"MISSING");
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

static int (*orig_decPre)(id, SEL, id, id, void *, BOOL);
static int new_decPre(id self, SEL _cmd, id data, id addr, void *out, BOOL stateless) {
    int r = orig_decPre(self, _cmd, data, addr, out, stateless);
    FZ(@"FckZck: Coordinator.decryptPreKeyCiphertext len=%lu addr=%@ stateless=%d -> %d",
       (unsigned long)[(NSData *)data length], FZAddr(addr), stateless, r);
    return r;
}

static int (*orig_decReg)(id, SEL, id, id, void *);
static int new_decReg(id self, SEL _cmd, id data, id addr, void *out) {
    int r = orig_decReg(self, _cmd, data, addr, out);
    FZ(@"FckZck: Coordinator.decryptRegularCiphertext len=%lu addr=%@ -> %d",
       (unsigned long)[(NSData *)data length], FZAddr(addr), r);
    return r;
}

static BOOL gSignalHooked = NO;
static BOOL FZInstallSignalHooks(void) {
    if (gSignalHooked) return YES;
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

%ctor {
    FZLoadConfig();
    FZ(@"FckZck 1.15.0 loaded in %@", [[NSBundle mainBundle] bundleIdentifier]);
    if (!FZInstallUserAgentHooks()) {
        FZ(@"FckZck: WAPBClientPayload_UserAgent not found yet, retrying in 3s");
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            if (!FZInstallUserAgentHooks()) FZ(@"FckZck: WAPBClientPayload_UserAgent still not found");
        });
    }
    // class dump disabled in 1.12 (classes3 already captured); re-enable FZDumpClassesMatching(...) if needed
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
