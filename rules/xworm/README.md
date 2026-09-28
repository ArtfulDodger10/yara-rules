# XWorm

XWorm is a .NET remote access trojan sold as malware-as-a-service since 2022. It offers a remote shell, keylogging, screenshots, a crypto clipboard hijacker, USB spreading, HTTP flooding, and a plugin system. Buyers get a builder, so every campaign's payload carries its own config.

Full analysis, config extractor and IOCs: [xworm-analysis](https://github.com/ArtfulDodger10/xworm-analysis)
Reports: [phishing to RAT](https://artfuldodger10.github.io/posts/Xworm-Analysis/), [VBScript downloader](https://artfuldodger10.github.io/posts/XWorm-RAT-Malware-Analysis/)

Rules: [xworm.yar](xworm.yar)

## Sample

| | |
|---|---|
| SHA256 | `9ef39965263531f35203eea0a1924181264cf6d7f3832d939cd532d5fad77a2d` |
| Type | PE32, .NET, XWorm V7.1 |
| Delivery | RAR attachment, JavaScript dropper, PowerShell loader, hollowed into `MSBuild.exe` |
| C2 | `109.248.150.234:1012` over raw TCP |
| Mutex | `aGO284VKfQVe8Vup` |

## Config

Every setting is Base64 AES-256-ECB. The key is `MD5(mutex)` written into a 32-byte buffer twice, the second copy starting at offset 15:

```
key[0:16]  = MD5(mutex)
key[15:31] = MD5(mutex)      key[15] ends up as digest[0], key[31] stays 0
```

The config itself can't be used for detection: it is encrypted, and each build has different values.

## Choosing what to match

| Indicator | Where | Used | Reason |
|---|---|---|---|
| C2 command names (`StartDDos`, `PCShutdown`, `OfflineGet`, `Xchat`...) | #US | family rule, 7 of 12 | the command handler compares them as plaintext, and they persist across versions |
| mutex `aGO284VKfQVe8Vup` | #US | campaign rule | one build only |
| obfuscated namespaces `AC1_1.OrderWorkflow`, `ProcessFulfillment`, class `AlgorithmAES` | #Strings | campaign rule | this build's obfuscation |
| `Read-StreamConfig`, MSBuild path, AES key bytes | PowerShell loader | loader rule | stage 2 of this campaign |
| host, port, keys, install name | config | no | encrypted, different per build |

XWorm V3.0 lacks `RunShell` and `RemovePlugins`, which is why the family rule asks for 7 of the 12 names and not all of them.

## Rules

| Rule | Scan | Matches |
|---|---|---|
| `XWorm_Payload_Generic` | files | any unpacked XWorm payload, V3.0 to V7.4 |
| `XWorm_Campaign_202609_Payload` | files | the V7.1 build from the September 2026 campaign |
| `XWorm_Campaign_202609_PS_Loader` | scripts, memory | the stage 2 PowerShell loader of that campaign |

## Testing

| Test | Result |
|---|---|
| 9 unpacked payloads, V3.0 to V7.4 | generic rule 9/9, campaign rule 1/1 (only its own build) |
| Loaders and crypted builds from the same set | 0 hits, as expected (the payload is encrypted inside them) |
| `C:\Windows\System32` | 0 hits |
| PowerShell loader rule on the stage 2 script | not tested yet, the script isn't in the sample set |
| Rule logic (synthetic test assemblies) | passes, see [tests](../../tests/test_rules.py) |

Sample hashes for the whole test set are listed in the [extractor README](https://github.com/ArtfulDodger10/xworm-analysis/tree/main/tools/xworm_extractor#tested-samples).
