# FckZck

Keep WhatsApp alive on old, jailbroken iOS devices.

> Hi! I'm Fabián, a student from Chile who likes bringing old devices back to life (legacy macOS, Hackintosh builds, retro hardware). I noticed that FckZck is no longer maintained by its original creator, so I'm going to **continue the project**: keep it working as WhatsApp changes, fix what was left unfinished, and document everything so others can use it.

## What is it?

WhatsApp keeps raising its minimum requirements. On an old iPhone you hit two walls:

1. **The client-side wall**: a banner or screen telling you to update from the App Store.
2. **The server-side wall**: even if you hide that banner, WhatsApp's server closes the connection (or refuses to show a login QR) because the app reports an outdated version.

[blockWAUpdates](https://github.com/0xkuj/blockWAUpdates) deals with the first wall. FckZck deals with the second: it tells WhatsApp (and, through it, the server) that this is a current build, so the connection stays open.

## What does it do?

- Reports a recent app version (`2.26.38.74`) to the server, with a build hash that matches that version, so the two are consistent.
- Overrides the app expiration, build date and deprecated-platform cut-off dates.
- **New in 1.1.0:** disables the *deprecated platform* check (`WAIsPlatformDeprecated` and `WAShouldShowPlatformDeprecationNags`), which the original author left as a commented-out "Somebody please fix this". The fix is looking the symbols up inside the `SharedModules` framework image (with the leading underscore) instead of using a `NULL` image.
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

- Make the spoofed version configurable without recompiling.
- Track WhatsApp's current version numbers and keep the defaults up to date.
- Rootless jailbreak support.
- Collect reports of which iOS / WhatsApp combinations work.

## Disclaimer

This is an unofficial project. It is not affiliated with, endorsed by, or connected to WhatsApp or Meta. Using it may go against WhatsApp's terms of service and could put your account at risk, so use it at your own risk (a secondary number is a good idea). It is meant for keeping old hardware useful.

## Credits

- **ifilipis**, original author of FckZck.
- **0xkuj**, author of blockWAUpdates, which the original project builds on.
