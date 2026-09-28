# AsyncRAT

AsyncRAT is an open-source .NET remote access trojan, published on GitHub in 2019 as a remote administration tool. Because the source is public, builds are recompiled and modified freely and no two samples look quite the same. It offers a remote shell, keylogging, screenshots, file and process management, persistence, anti-analysis checks, and a TLS-wrapped C2 channel with an AES-encrypted config.

Rules: [asyncrat.yar](asyncrat.yar)

## Sample

| | |
|---|---|
| SHA256 | `3dbaf616dcaacfcf66909b7a3404d1536f9e0d230b3b59934f1ccc6fe3e20554` |
| Type | PE32 GUI, .NET, 32-bit |
| Compiled | 2023-10-16 21:40:53 UTC |
| Imports | `mscoree.dll` only, imphash `f34d5f2d4577ed6d9ceec516c1f5a744` |
| Sections | `.text` 5.62 entropy, `.rsrc` 6.30, `.reloc` 0.08 |
| Version info | impersonates WinRAR 7.5.6.1 (`RarLab`, `WinRar`) |
| Sandbox | [ANY.RUN](https://app.any.run/tasks/2fa8f14b-f2ac-45d4-9b72-18e1f595e383), Triage 10/10 |

Class and method names are randomized, so the code has to be read by behavior.

## Config

Extracted by ANY.RUN and confirmed by Triage:

| Field | Value |
|---|---|
| Version | 0.5.8 |
| Group | `xTeam` |
| C2 | `hubscore.io`, ports 8090, 7080, 443, 80 (behind Cloudflare) |
| Mutex | `rxUf9crL1mff` |
| Install | off (would copy to `%AppData%\c2.skyupdragon.io.exe`) |
| AutoRun | off |
| BSoD on kill | on |
| Anti-VM | on |

## How the config is protected

The config loader (`NmxKiSWCMEb.VkUXWPRuNNeIB`) decodes a Base64 key, derives the AES key with PBKDF2, and decrypts each field on its own:

| | |
|---|---|
| KDF | `Rfc2898DeriveBytes`, 50,000 iterations |
| Password | `uboPUIGxH1wbTAls9Pf7vNmiOAHEUlnt` |
| Salt | `bfeb1e56fbcd973bb219022430a57843003d5644d21e62b9d4f180e7e6c33941` |
| Derived key | `42ef5c76d82323e50a62f28fb34230e4b2871810f45eb66dc04e0fcd765968a6` |
| Cipher | AES-256-CBC, PKCS7 |
| Integrity | HMAC-SHA256 over the ciphertext, checked before decrypting |

It then loads an embedded self-signed certificate (`CN=AsyncRAT Server`) and checks an RSA signature over the config (`TPobVYcTtGvhWE`). If any check fails the client exits, so a tampered config never runs.

## Execution

```
Main
  wait 3 seconds
  decrypt config, verify HMAC and RSA signature
  create mutex rxUf9crL1mff, exit if it already exists
  anti-analysis: VirtualBox, SbieDll.dll, CheckRemoteDebuggerPresent
  profile the host: GUID, hostname, OS, language, AV through WMI SecurityCenter2
  install to %AppData%\c2.skyupdragon.io.exe (off in this build)
  schtasks /create /f /sc onlogon /rl highest (off in this build)
  RtlSetProcessIsCritical, so killing the process blue-screens the machine
  C2 loop: TcpClient, SslStream, AES, hubscore.io:7080
```

## Choosing what to match

| Indicator | Where | Used | Reason |
|---|---|---|---|
| `AesCryptoServiceProvider`, `Rfc2898DeriveBytes`, `HMACSHA256` | #Strings | yes, all three | framework names that renaming obfuscators can't touch |
| `SslStream`, `AuthenticateAsClient`, `TcpClient` | #Strings | yes, all three | the C2 transport, same reason |
| `RtlSetProcessIsCritical`, `CheckRemoteDebuggerPresent` | P/Invoke | one of the two | rare outside malware and debugging tools |
| `schtasks ... /sc onlogon /rl highest`, `SbieDll.dll`, `VirtualBox`, AV WMI query | #US | two of these | behavior strings from the source code |
| C2, mutex, install file name | config | memory rule only | AES-encrypted on disk |
| `Hosts`, `Ports`, `MTX`, `Anti` | field names | no | far too common, and `Anti` also matches inside `AntivirusProduct` |

Any one group on its own is common in legitimate software. The rule needs all of them together.

## Rules

| Rule | Scan | Matches |
|---|---|---|
| `AsyncRAT_Payload_Generic` | files | the full crypto stack, the full C2 stack, one of the two P/Invokes, and two behavior strings |
| `AsyncRAT_Campaign_xTeam_Memory` | memory dumps | two of the C2 domain, mutex and install name |

## Testing

| Test | Result |
|---|---|
| Sample `3dbaf616...` | `AsyncRAT_Payload_Generic` matches |
| 9 XWorm payloads and their loaders (should not match) | 0 hits |
| Process memory dump | not tested yet, no dump in the sample set |
| `C:\Windows\System32`, 15,468 files | 0 hits |
| .NET Framework and Program Files | see the [main README](../../README.md#false-positive-testing) |
| Rule logic (synthetic test assemblies) | passes, see [tests](../../tests/test_rules.py) |

## Changes from the first version

The first version (`AsyncRAT_cooked`) did not compile, because `$anti_debug` was declared and never used. Beyond that, several branches of its condition could match on their own:

- AES, PBKDF2 and HMAC together, which any .NET program using standard crypto has
- `TcpClient` and `SslStream` with two of `Hosts`, `Ports`, `MTX`, `Anti`, which most networked apps satisfy
- the install file name, which is encrypted on disk and never matched

The new rule requires all the groups together, and moves config values to a memory rule.
