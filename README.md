# FckZck

Keep WhatsApp alive on old, jailbroken iOS devices.

> Hi! I'm Fabián, a student from Chile who likes bringing old devices back to life (legacy macOS, Hackintosh builds, retro hardware). I noticed that FckZck is no longer maintained by its original creator, so I'm going to **continue the project**: keep it working as WhatsApp changes, fix what was left unfinished, and document everything so others can use it.

## What is it?

WhatsApp keeps raising its minimum requirements. On an old iPhone you hit two walls:

1. **The client-side wall**: a banner or screen telling you to update from the App Store.
2. **The server-side wall**: even if you hide that banner, WhatsApp's server closes the connection (or refuses to show a login QR) because the app reports an outdated version.

[blockWAUpdates](https://github.com/0xkuj/blockWAUpdates) deals with the first wall. FckZck deals with the second: it tells WhatsApp (and, through it, the server) that this is a current build, so the connection stays open.

## What does it do?

- Reports a recent app version (default `2.26.38.74`, **configurable**, see below) to the server, with a build hash that is always the MD5 of that version string, so the two are consistent.
- Overrides the app expiration, build date and deprecated-platform cut-off dates.
- **1.1.0:** disables the *deprecated platform* check (`WAIsPlatformDeprecated` and `WAShouldShowPlatformDeprecationNags`), which the original author left as a commented-out "Somebody please fix this". The fix is looking the symbols up inside the `SharedModules` framework image (with the leading underscore) instead of using a `NULL` image.
- Disables the in-app "build expired" check.
- Works for WhatsApp and WhatsApp Business (including their notification and service extensions).

## Status

- Tested by me on a **jailbroken iPhone running iOS 12** with **WhatsApp 2.25.1.83** (the last version the App Store still offers there). Login, QR and messaging worked with the 1.0-style build; the new deprecated-platform hooks in 1.1.0 are fresh, so please report what you see.
- Not tested on other iOS versions.
- This is a cat-and-mouse game: WhatsApp can change what its server accepts at any time, and this tweak may stop working without warning.

## Install

1. Download the latest `.deb` from the [Releases](../../releases) page.
2. Install it with Filza (tap the `.deb` > Install) or with `dpkg -i` from a terminal.
3. **Remove other tweaks that change WhatsApp's version** (Axolotl, WALegacy, older FckZck builds). They hook the same functions and fight each other.
4. Force-quit WhatsApp, respring, and open it.

Also recommended: turn off automatic App Store updates so WhatsApp is not replaced by a newer version your device can't run.

## Configuration

Since 1.2.0 the spoofed version can be changed **without recompiling**. The package installs

`/var/mobile/Library/Preferences/com.ifilipis.fckzck.plist`

```xml
<key>version</key>
<string>2.26.38.74</string>
```

Edit the string (Filza works), force-quit WhatsApp and open it again. No respring needed. Accepted formats: `2.26.38.74` (four parts) or `26.38.74` (three parts, a leading `2` is added). If the file is missing or invalid, the default is used.

## Debug log

The tweak writes `fckzck.log` to the WhatsApp app container (`Documents/`), reset on every launch. It contains the tweak's own lines (which hooks worked, which version was applied) plus the WhatsApp internal log lines about connection, pairing/linking, crypto and errors. Search for it with Filza. It may contain account identifiers, so redact it before sharing.

## 1.26 (fix: WhatsApp se desvincula ~2 min después de vincular, iOS 12)

Causa (según `fckzck.log`): el servidor entrega INITIAL_BOOTSTRAP, pero en iOS 12 el código Swift de WhatsApp nunca llama a `handleInitialHistorySync` ni a `handleSecurityNotificationSetting`. A los ~120 s la app se auto-elimina con `remove-companion-device reason="history_sync_timeout"`. El chequeo de 1.25 miraba el payload *después* de que WhatsApp lo consumiera, por eso nunca se activaba.

Qué hace 1.26: detecta INITIAL_BOOTSTRAP con `hasInitialHistBootstrapInlinePayload` (antes de procesarlo), completa los dos pasos del bootstrap a mano, tiene un temporizador de respaldo (`forceFinishBootstrapSeconds`, 25 s) y bloquea el logout de razón 11 como última red de seguridad (`blockHistoryTimeoutLogout`, ON por defecto).

## 1.27 (historial no carga)

El bootstrap ya termina, pero el teléfono nunca manda chunks RECENT/FULL: decide según la config de historial que el equipo vinculado declara **al vincular**. 1.27 registra y sube esos límites (`historyFullSyncDaysLimit`, `historyFullSyncSizeMbLimit`, `historyStorageQuotaMb`, `historyRecentSyncDaysLimit`, `historyRequireFullSync` en el plist) y vuelca las clases en `fckzck-pairing-classes.txt`. Hay que **desvincular y volver a vincular** para que surta efecto.

## 1.28 (versión del bundle)

Un usuario de Reddit reporta que el aviso "tu teléfono ya no es compatible" al enviar desaparece si pone la fecha del teléfono en abril de 2025. 1.28 hace que `CFBundleVersion` y `CFBundleShortVersionString` de WhatsApp (leídos con `NSBundle` y `CFBundleGetValueForInfoDictionaryKey`) devuelvan la versión falsa (`26.38.74` y `2.26.38.74`). Claves del plist: `spoofBundleVersion`, `bundleShortVersion`, `bundleVersion`. También vuelca clases con "Deprecat/Unsupported/OSVersion" en `fckzck-deprecation-classes.txt`.

## Known limitations

- **Linking new devices does not work** on old WhatsApp builds, with this tweak or without it. Scanning a QR makes the server answer `400 bad-request`, and linking with a phone-number code fails on the phone with an AES-GCM decryption error. Both happen inside WhatsApp's own pairing code, which looks outdated compared to current companion clients. Changing the reported version does not seem to change this. Reports and ideas are welcome.

## Build from source

You need [Theos](https://theos.dev) and an iOS SDK.

```sh
make package
```

To change the spoofed version, edit `Tweak.xm`:

- `NEW_VERSION_STRING` and the four `%orig(...)` numbers in `WAPBClientPayload_UserAgent_AppVersion` (primary, secondary, tertiary, quaternary).
- `NEW_BUILD_HASH` is the MD5 of the version string:

```sh
echo -n "2.26.38.74" | md5sum
```

## Roadmap

- Find a way to make device linking work (see Known limitations).
- Track WhatsApp's current version numbers and keep the defaults up to date.
- Rootless jailbreak support.
- Collect reports of which iOS / WhatsApp combinations work.

## Disclaimer

This is an unofficial project. It is not affiliated with, endorsed by, or connected to WhatsApp or Meta. Using it may go against WhatsApp's terms of service and could put your account at risk, so use it at your own risk (a secondary number is a good idea). It is meant for keeping old hardware useful.

## Credits

- **ifilipis**, original author of FckZck.
- **0xkuj**, author of blockWAUpdates, which the original project builds on.


## 1.34
Rewrites the serialized pairing `deviceProps` in the outbound `ClientPayload` so `requireFullSync` is actually present in the registration bytes. The `runWhenInitialSyncFinished:` compatibility bypass is now one-shot: only the first call (the stage 3 -> stage 4 registration gate) runs early; later callbacks remain stock and wait for real history completion. The six-second UI finish was replaced with an adaptive 25-second fallback, extended when FULL/RECENT chunks are observed.
