# YARA Rules

Detection rules for malware families I have reversed. Every rule comes from my own analysis of a sample, each family folder explains why each string was chosen, and every rule is tested for false positives before it is added.

## Rules

| Family | Rule | Scan | Matches |
|---|---|---|---|
| [XWorm](rules/xworm/) | `XWorm_Payload_Generic` | files | any unpacked XWorm payload, V3.0 to V7.4 |
| | `XWorm_Campaign_202609_Payload` | files | V7.1 build from a September 2026 phishing campaign |
| | `XWorm_Campaign_202609_PS_Loader` | scripts, memory | that campaign's PowerShell loader |
| [AgentTesla](rules/agenttesla/) | `AgentTesla_Loader_FF_Resource` | files | loader that decrypts resource `FF` with a 22-byte XOR key |
| | `AgentTesla_Campaign_SMTP_Memory` | memory | SMTP exfiltration settings of the albushrametalic campaign |
| [AsyncRAT](rules/asyncrat/) | `AsyncRAT_Payload_Generic` | files | AsyncRAT client, by its crypto, C2 and anti-analysis traits |
| | `AsyncRAT_Campaign_xTeam_Memory` | memory | config of the xTeam 0.5.8 build |

Rules marked "memory" target values that are encrypted on disk. Use them on memory dumps (for example with Volatility's `yarascan`) or on unpacked payloads.

## False-positive testing

All rules were run against clean Windows files on 2026-09-28 with YARA 4.5.4:

| Set | Files | Hits |
|---|---|---|
| `C:\Windows\System32` | 15,468 | 0 |
| `C:\Windows\Microsoft.NET`, `C:\Program Files`, `C:\Program Files (x86)` | 130,193 | 0 |

## True-positive testing

| Rule | Samples | Result |
|---|---|---|
| `XWorm_Payload_Generic` | 9 XWorm payloads, V3.0 to V7.4 | 9/9 |
| `XWorm_Campaign_202609_Payload` | the same 9 | 1/1, only its own build |
| `AgentTesla_Loader_FF_Resource` | the analyzed loader | 1/1 |
| `AsyncRAT_Payload_Generic` | the analyzed client | 1/1 |

The AgentTesla and AsyncRAT rules were also run on the XWorm set, with no matches. The PowerShell loader rule and the two memory rules have not been run on real data yet, since the sample set has no stage 2 script or memory dumps. Details are in each family's README.

## Layout

```
rules/<family>/<family>.yar   the rules
rules/<family>/README.md      sample, analysis summary, string choices, test results
tools/yara_scan.py            scanner used for all testing
tests/test_rules.py           compile, metadata and rule logic tests
notes/                        my YARA learning notes
```

## Usage

```bash
pip install -r requirements.txt

# every rule in the repo against a folder
python tools/yara_scan.py path/to/samples

# one family, counts only (how the false-positive numbers above were produced)
python tools/yara_scan.py C:\Windows\System32 --rules rules/xworm --summary-only

# CSV with imphash and section entropy for each match
python tools/yara_scan.py path/to/samples -o report.csv --pe-info
```

The plain `yara` command line works too: `yara -r rules/xworm/xworm.yar path/to/samples`.

## Conventions

- Names follow `Family_Scope_Detail`: `Payload_Generic` for the whole family, `Loader_...` for a loader, `Campaign_<id>_...` for one campaign.
- Every rule has `description`, `author`, `date` and `family` in its meta, and `hash` where it came from one sample. The tests check this.
- Strings are only used in the rule for the file they actually live in. Config values that are encrypted on disk go in memory rules.
- Framework and P/Invoke names are preferred over user strings for .NET families, since renaming obfuscators can't change them.

## Tests

```bash
python -m unittest discover -s tests -v
```

Besides compiling every file and checking metadata, the tests build small C# programs at test time, each containing just the names and strings one rule looks for, together with near-misses that must not match. A condition that gets loosened or broken fails here. GitHub Actions runs the tests on every push.

## Notes

[notes/](notes/) holds what I wrote while learning YARA: syntax and conditions, the `pe`, `math` and `dotnet` modules, and scanning with yara-python and pefile.

MIT License
