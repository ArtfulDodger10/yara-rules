# AgentTesla

AgentTesla is a .NET infostealer and keylogger sold as malware-as-a-service since 2014. It steals credentials from browsers, mail, FTP and VPN clients, logs keystrokes, takes screenshots, and exfiltrates over SMTP, FTP or HTTP.

Full report: [AgentTesla RAT, full malware analysis](https://artfuldodger10.github.io/posts/AgentTesla-RAT-Full-Malware-Analysis-Report/)

Rules: [agenttesla.yar](agenttesla.yar)

## Sample

| | |
|---|---|
| SHA256 | `1ca6c053e788f8ea1e1eec1c712cf0ec5374ba5d8caf432717842c702e3cda0e` |
| Type | PE32 GUI, .NET Framework 4 (CLR v4.0.30319) |
| Assembly | `dnqK`, version 1.2.2.0, compiled 2024-05-30 22:21:36 |
| Imports | `mscoree.dll` only, imphash `f34d5f2d4577ed6d9ceec516c1f5a744` |
| Sections | `.text` 7.98 entropy (700,416 bytes), `.rsrc` 7.02, `.reloc` 0.02 |

DIE flags it as packed. The `.text` entropy comes from an encrypted managed resource, not from a native packer.

## The loader

The entry point `QQ復複覆.Program.Main` only starts a Windows Forms window, `frmMain`, dressed up as an image filter tool. The Chinese namespace is there to get in the way of analysts and tooling.

The real work happens in `frmMain.InitializeComponent()`. It reads managed resource `FF` (69,121 bytes) and decrypts it in place:

```csharp
byte[] data = (byte[])resources.GetObject("FF");

for (int i = 0; i < data.Length; i++) {
    byte xorResult = Encoding.Default.GetBytes("PY718E785ZXFG4844GPE4Z")[i % 22];
    int r    = (int)(data[i] ^ xorResult);
    int g    = (int)data[(i + 1) % data.Length];
    int last = r - g + 256 & 255;
    data[i]  = (byte)last;
}
```

Each byte is XORed with the 22-byte key, then the next byte is subtracted, mod 256. The result is loaded straight into memory and started through reflection, so the next stage never touches disk:

```csharp
Assembly Wr_99 = Assembly.Load(data);
Type airo = Wr_99.GetTypes()[1];
typeof(Activator).InvokeMember("CreateInstance", BindingFlags.InvokeMethod, null, null,
    new object[] { airo, this.GetInitializationParameters(frmMain.EIK) });
```

## Exfiltration config

Taken from the Triage memory dump of the final stage:

| Field | Value |
|---|---|
| Protocol | SMTP, port 587 (STARTTLS) |
| Server | `mail.albushrametalic.com` |
| Sender account | `mustafa@albushrametalic.com` |
| Password | `GLBL1285#` |
| Recipient | `saeed9797seead@gmail.com` |

## Choosing what to match

The loader and the final payload are different files, so each indicator only belongs in a rule for the file it actually lives in.

| Indicator | Found in | Used | Reason |
|---|---|---|---|
| `PY718E785ZXFG4844GPE4Z` | loader, #US heap | yes | the key itself, unique to this loader |
| `QQ復複覆` namespace | loader, #Strings heap | yes, with the module name | obfuscation choice, changes per build |
| `dnqK.exe` module name | loader | yes, with the namespace | weak alone |
| `.text` entropy above 7.5 | loader | yes, with the namespace | encrypted resource, hard to avoid |
| SMTP server, accounts, password | final stage, memory only | memory rule | encrypted inside `FF` on disk |
| `Assembly.Load` | loader | no | .NET stores `Assembly` and `Load` as separate names, so the string never appears |
| `api.ipify.org` | final stage | no | used by plenty of legitimate software |
| resource name `FF` | loader | no | two characters, useless alone |
| one import, three sections | loader | no | true for almost every .NET executable |

## Rules

| Rule | Scan | Matches |
|---|---|---|
| `AgentTesla_Loader_FF_Resource` | files | the loader, by its key, or by the namespace and module name plus the encrypted `.text` |
| `AgentTesla_Campaign_SMTP_Memory` | memory dumps, unpacked payloads | any two of the SMTP server, sender, password and recipient |

There is no family-wide rule yet. The loader is a crypter that changes between campaigns, so a family rule has to be built from the unpacked final stage. That needs the stage 2 and 3 payloads from the lab.

## Testing

| Test | Result |
|---|---|
| Loader sample `1ca6c053...` | `AgentTesla_Loader_FF_Resource` matches |
| 9 XWorm payloads and their loaders (should not match) | 0 hits |
| Final stage memory dump | not tested yet, no dump in the sample set |
| `C:\Windows\System32`, 15,468 files | 0 hits |
| .NET Framework and Program Files | see the [main README](../../README.md#false-positive-testing) |
| Rule logic (synthetic test assemblies) | passes, see [tests](../../tests/test_rules.py) |

## Changes from the first version

The first version of this rule (in the old day-by-day notes) did not compile:

- the `reference` URL was split over two lines inside a quoted string
- `pe.number_of_imported_symbols` is not a field of the `pe` module; `pe.number_of_imports` is the DLL count

It also mixed loader and final-stage strings in one condition, so the SMTP strings could never match the file on disk, and `Assembly.Load` could never match at all. Those are now split into a file rule and a memory rule.
