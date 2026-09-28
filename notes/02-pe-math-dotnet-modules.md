# The pe, math and dotnet modules

---

## Part 1: the pe module

### Imports

Malware behavior is defined by what Windows APIs it calls.

```yara
import "pe"

// Check if a specific DLL + function is imported
pe.imports("kernel32.dll", "VirtualAllocEx")

// Check if a DLL is imported at all
pe.imports("wininet.dll")

// Count total imported symbols
pe.number_of_imported_functions < 5  // suspicious, may resolve APIs at runtime
pe.number_of_imported_symbols > 200  // large import table
```

**Common import combinations worth memorizing:**

```
Process Injection:
  VirtualAllocEx + WriteProcessMemory + CreateRemoteThread

Keylogging:
  SetWindowsHookEx + GetAsyncKeyState + CallNextHookEx

Credential Theft:
  CryptUnprotectData  (decrypts Chrome/Firefox stored passwords)

Anti-Analysis:
  IsDebuggerPresent + CheckRemoteDebuggerPresent + NtQueryInformationProcess

Network:
  InternetOpenA/W + InternetConnectA/W + HttpSendRequestA/W  (WinInet)
  WSAStartup + connect + send + recv                         (raw Winsock)
```

---

### Sections

```yara
pe.number_of_sections > 8    // unusual, most legitimate PEs have 4 to 6
pe.number_of_sections < 3    // suspicious, stripped binary

// Check for a specific section name
for any section in pe.sections : (
    section.name == ".text"
)

// Writable + Executable section = code injection target or packed code
for any section in pe.sections : (
    (section.characteristics & pe.SECTION_MEM_WRITE)   != 0 and
    (section.characteristics & pe.SECTION_MEM_EXECUTE) != 0
)

// Unusual or blank section name
for any section in pe.sections : (
    section.name == ""
)
```

---

### Entry Point

**This rule checks if the entry point is located inside a non-standard section, a common malware trick.**

```yara
pe.entry_point    // raw file offset of the entry point

for any section in pe.sections : (
    pe.entry_point >= section.raw_data_offset and
    pe.entry_point  < section.raw_data_offset + section.raw_data_size and
    section.name   != ".text"
)
```

**Logic breakdown:**

- `raw_data_offset`: where the section's data starts in the physical file
- `raw_data_size`: how many bytes the section occupies in the file
- `.text`: the standard section where the entry point lives, so it's suspicious if the EP is elsewhere
- `pe.entry_point >= section.raw_data_offset`: the EP is at or after the start of this section
- `pe.entry_point < section.raw_data_offset + section.raw_data_size`: the EP is before the end of this section (offset + size = end)
- `section.name != ".text"`: that section is not the standard code section

Overall: the rule matches if the entry point falls **inside** a section that is **not** named `.text`.

---

### Other Useful PE Fields

```yara
pe.machine == pe.MACHINE_I386     // 32-bit binary
pe.machine == pe.MACHINE_AMD64    // 64-bit binary

pe.is_dll                         // it's a DLL
pe.is_exe                         // it's an EXE

pe.overlay.size > 0               // data appended after the last PE section
pe.overlay.size > 100KB           // large overlay, possibly an embedded payload
```

---

## Part 2: the math module

Helps detect packing, encryption, and obfuscation statistically.

**Entropy reference:**

| Range   | Meaning                              |
| ------- | ------------------------------------ |
| < 7.0   | Probably fine, normal code or data   |
| 7.0–7.4 | Worth investigating                  |
| > 7.4   | Strong packing or encryption signal  |
| > 7.8   | Almost certainly packed or encrypted |

```
Normal .text sections:          ~5.5–6.5
UPX-packed sections:            ~7.8–7.9
AES-encrypted blobs:            ~7.9–8.0
Resource sections with PEs:     ~7.5+
```

### Entropy

```yara
import "pe"
import "math"

// Any section with suspiciously high entropy
for any section in pe.sections : (
    math.entropy(section.raw_data_offset, section.raw_data_size) > 7.2
)

// Specifically the executable section
for any section in pe.sections : (
    (section.characteristics & pe.SECTION_MEM_EXECUTE) != 0 and
    math.entropy(section.raw_data_offset, section.raw_data_size) > 7.0
)
```

**There are also extra uses of the math module like `math.mean()`, and `math.deviation()`, , useful for shellcode detection, which may be used later**

### Entropy Combined with PE Structure

```yara
import "pe"
import "math"

rule Packed_Executable {
    meta:
        description = "PE with a high-entropy section and few imports, likely packed"

    condition:
        pe.is_pe and
        filesize < 5MB and
        pe.number_of_imported_functions < 10 and  // few imports = dynamic API resolution
        for any section in pe.sections : (
            math.entropy(section.raw_data_offset, section.raw_data_size) > 7.4
        )
}
```

---

## Part 3: the dotnet module

There is `dotnet.is_dotnet` the same way like `pe.is_pe` :)

```yara
import "dotnet"

dotnet.is_dotnet               // is this a .NET assembly?
dotnet.assembly.name           // assembly name from metadata
dotnet.assembly.version.major  // major version number
dotnet.number_of_streams       // number of metadata streams
```

**Version breakdown:**

```
version = 5.2.1.7
  major    = 5
  minor    = 2
  build    = 1
  revision = 7
```

**Metadata streams** are like sections but for .NET metadata:

```
#~        compressed metadata tables (classes, methods, fields)
#Strings  class names, method names, namespaces
#Blob     binary data (signatures, constants)
#GUID     unique identifiers
#US       user strings (hardcoded strings in code)
```

`#Strings` is the most useful for detection. It holds class names, method names, and namespaces that can reveal malware behavior.

### Streams

```yara
// Check for a specific stream
for any stream in dotnet.streams : (
    stream.name == "#Strings"
)

dotnet.number_of_streams > 0
```

### Imported Modules

```yara
// .NET assembly importing a native DLL
for any module_ref in dotnet.module_refs : (
    module_ref == "kernel32.dll"    // .NET calling native Win32, suspicious
)
```

A pure .NET application calling `kernel32` directly via P/Invoke is not inherently malicious, but combined with other signals (keylogger strings, credential paths) it becomes meaningful.

---

### Using dotnet as a gate

Using `dotnet.is_dotnet` as the first condition immediately rules out every non-.NET file, which cuts false positives for free.

```yara
import "dotnet"

rule AgentTesla_Gate {
    strings:
        $smtp    = "smtp" wide ascii nocase
        $keylog  = "GetAsyncKeyState" ascii
        $browser = "\\Chrome\\User Data" wide ascii

    condition:
        dotnet.is_dotnet and
        2 of ($smtp, $keylog, $browser)
}
```

---

## The 4 Practice Rules

### Rule 1: high entropy packer

```yara
import "pe"
import "math"

rule High_Entropy_Section {
    meta:
        description = "PE file with a high-entropy section, possibly packed or encrypted"

    condition:
        pe.is_pe and
        filesize < 10MB and
        for any section in pe.sections : (
            math.entropy(section.raw_data_offset, section.raw_data_size) > 7.2
        )
}
```

### Rule 2: process injection imports

```yara
import "pe"

rule Process_Injection_Loader {
    meta:
        description = "PE importing the classic Win32 process injection API combination"

    condition:
        pe.is_pe and
        filesize < 5MB and
        pe.imports("kernel32.dll", "VirtualAllocEx") and
        pe.imports("kernel32.dll", "WriteProcessMemory") and
        pe.imports("kernel32.dll", "CreateRemoteThread")
}
```

### Rule 3: .NET with native calls or high entropy

Combines `pe`, `math`, and `dotnet` modules together.

```yara
import "dotnet"
import "pe"
import "math"

rule Suspicious_DotNet_NativeCalls {
    meta:
        description = ".NET assembly importing native injection APIs or containing a high-entropy section"

    condition:
        dotnet.is_dotnet and
        filesize < 3MB and
        (
            for any section in pe.sections : (
                math.entropy(section.raw_data_offset, section.raw_data_size) > 7.0
            )
        ) and
        (
            pe.imports("kernel32.dll", "VirtualAlloc") or
            pe.imports("kernel32.dll", "WriteProcessMemory")
        )
}
```

### Rule 4: overlay dropper

**What is an overlay?** Any data appended after the last legitimate PE section. Think of it like:

```bash
copy /b program.exe + secret.bin infected.exe
```

The appended `secret.bin` becomes the overlay. It could be a ransomware payload, a second-stage binary, or any embedded file dropped at runtime.

```yara
import "pe"
import "math"

rule Overlay_Dropper {
    meta:
        description = "PE with a large high-entropy overlay, likely an embedded payload"

    condition:
        pe.is_pe and
        pe.overlay.size > 50KB and
        math.entropy(pe.overlay.offset, pe.overlay.size) > 7.0
}
```

---

### Testing the rules

**These are the 3 Rules I will use with light modifications** 
##### Rule 1
```yara
import "pe"

rule Classic_Process_Injection {
    meta:
        description = "PE importing the classic Win32 process injection API triad"

    condition:
        pe.is_pe and
        filesize < 5MB and
        pe.imports("kernel32.dll", "VirtualAllocEx") and
        pe.imports("kernel32.dll", "WriteProcessMemory") and
        pe.imports("kernel32.dll", "CreateRemoteThread")
}
```

##### Rule 2
```yara
import "pe"
import "math"

rule High_Entropy_Packed_PE {
    meta:
        description = "PE with a high-entropy section, likely packed or encrypted"

    condition:
        pe.is_pe and
        filesize < 10MB and
        for any section in pe.sections : (
            math.entropy(section.raw_data_offset, section.raw_data_size) > 7.2
        )
}
```

##### Rule 3
```yara
import "pe"
import "math"
import "dotnet"

rule Suspicious_DotNet_NativeCalls {
    meta:
        description = ".NET assembly importing native injection APIs or containing high-entropy section"

    condition:
        dotnet.is_dotnet and
        filesize < 5MB and
        (
            (
                pe.imports("kernel32.dll", "VirtualAlloc") or
                pe.imports("kernel32.dll", "WriteProcessMemory") or
                pe.imports("kernel32.dll", "CreateRemoteThread")
            )
            or
            for any section in pe.sections : (
                math.entropy(section.raw_data_offset, section.raw_data_size) > 7.0
            )
        )
}
```
---
---
---
**I will use first 2 on my `classic_injection.exe`, u can find the corresponding C code [here](https://github.com/ArtfulDodger10/sysmon-mirage-v2/blob/main/Injectors/Classic%20Injection/classic_injection.c)**


And here we go, It did work well
```bash
C:Users/nader/Desktop/YARA Rules$ yara process_injection.yar classic_injection.exe

Classic_Process_Injection classic_injection.exe
```
---

**For Rule 2 I will pack the same exe with UPX, then try the second rule on it**

and here we go again, It did work
```bash
C:Users/nader/Desktop/YARA Rules$ upx classic_injection.exe -o classic_packed.exe
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2024
UPX 4.2.2       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 3rd 2024

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
     61203 ->     46867   76.58%    win64/pe     classic_packed.exe

Packed 1 file.
C:Users/nader/Desktop/YARA Rules$ yara check_entropy_for_packed_samples.yar classic_packed.exe

High_Entropy_Packed_PE classic_packed.exe  // well well well
```
---
**And the final one**
I just will try it on this little `hello_from_.NET` program 
```csharp
using System;

class Program
{
    static void Main()
    {
        Console.WriteLine("Hello from .NET!");
    }
}
```

and I got nothing :), which is expected btw.
```bash
C:Users/nader/Desktop/YARA Rules$ yara check_Dot_Net.yar hello.exe
C:Users/nader/Desktop/YARA Rules$
```
**only 2 conditions matched, but the third big one did not.

Okay I will remove it, and apply the rule like this
```yara
import "dotnet"
rule check_DotNet {
	meta: 
		description = "Simple .NET check" 
		condition: 
			dotnet.is_dotnet 
			
} 
```

**And here we go again**
```bash
C:Users/nader/Desktop/YARA Rules$ yara check_Dot_Net.yar hello.exe
check_DotNet hello.exe
```

**Why the native-call branch never matched:** a .NET assembly calls Win32 APIs through P/Invoke (`[DllImport]`), and P/Invoke targets are recorded in the .NET metadata (the ImplMap table), not in the PE import table. `pe.imports()` only sees the import table, which for .NET is `mscoree.dll` alone, so that condition can never be true for a managed assembly. To detect P/Invoke use, match the API name as a string (it is stored in the #Strings heap), as the AsyncRAT rule in this repo does with `RtlSetProcessIsCritical`.

---
