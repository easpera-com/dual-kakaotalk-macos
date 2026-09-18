# Feasibility and CoreUI Decision
[한국어](FEASIBILITY.md) | [English](FEASIBILITY.en.md)

Status: **EXPERIMENTAL BETA — PRIVATE API, FINGERPRINT-GATED**

## Verified baseline

The Intel verification machine runs macOS 13.7.8 (22H730). Its official KakaoTalk 26.8.0 (2000) has bundle identifier `com.kakao.KakaoTalkMac`, Team ID `L75WVXX68A`, a valid strict deep signature, and a Universal x86_64/arm64 executable. Exact non-asset compatibility facts are recorded in `compatibility.json`.

The Dock icon is re-derived locally through public AppKit: the bundle's existing `.icns` is read, only the yellow field is hue-rotated to green (`#32C67A`), `/usr/bin/iconutil` rebuilds it, and it is replaced inside the staged copy alone. It uses no private API and no fingerprint allowlist, so it works across KakaoTalk versions. The dual app is still labeled `Dual KakaoTalk` in the Dock and app switcher. If the app overrides its own icon at runtime through `NSApplication.applicationIconImage`, the running Dock icon may still show the original, which needs physical-device confirmation. Its green menu-bar states reside in `Contents/Resources/Assets.car`; macOS provides no public writer API for that compiled format.

## Current implementation

The project owner explicitly accepted the private-API risk. The beta therefore uses a small Objective-C bridge to undocumented CoreUI classes. It:

- accepts only an exact allowlisted source-catalog SHA-256;
- addresses only eight named menu icons at 1x and 2x;
- checks expected dimensions and link structure before mutation;
- patches a staged copy, never the official app;
- validates the resulting catalog and requires its hash to change;
- signs and verifies the completed staged app before replacement;
- rolls back the prior `KakaoTalkWork.app` on failure.

The bridge declarations are independently implemented from observed runtime selectors and MIT-licensed CoreUI header information. No third-party implementation, Kakao executable, or Kakao asset bytes are vendored.

## Residual risk

CoreUI is private and may change in any macOS update. Catalog internals may change in any KakaoTalk update. Ad-hoc signing can trigger security prompts. The Universal output is physically verified on Intel macOS 13.7.8 and Apple M3 macOS 26.5.2; other combinations remain experimental. Every unknown catalog fails closed and is reported through the compatibility issue flow.

## Follow-up

A separately tracked goal researches an independent writer for only the required `Assets.car` subset. It must preserve non-target records byte-for-byte where possible, provide round-trip and corruption tests, and replace the private bridge only after parity is demonstrated. Until then, the private bridge remains clearly labeled experimental.
