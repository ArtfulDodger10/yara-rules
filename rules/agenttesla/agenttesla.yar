/*
    AgentTesla detections
    Artful Dodger
    https://artfuldodger10.github.io/posts/AgentTesla-RAT-Full-Malware-Analysis-Report/

    AgentTesla_Loader_FF_Resource      stage 1 loader on disk
    AgentTesla_Campaign_SMTP_Memory    SMTP config in the unpacked payload or a memory dump
*/

import "pe"
import "math"
import "dotnet"

rule AgentTesla_Loader_FF_Resource
{
    meta:
        description = "AgentTesla loader posing as an image filter app. XOR-decrypts managed resource FF and runs it with Assembly.Load"
        author      = "Artful Dodger"
        date        = "2026-09-28"
        family      = "AgentTesla"
        reference   = "https://artfuldodger10.github.io/posts/AgentTesla-RAT-Full-Malware-Analysis-Report/"
        hash        = "1ca6c053e788f8ea1e1eec1c712cf0ec5374ba5d8caf432717842c702e3cda0e"

    strings:
        // XOR key passed to Encoding.Default.GetBytes, stored as a user string
        $xor_key  = "PY718E785ZXFG4844GPE4Z" ascii wide
        // namespace QQ復複覆 as UTF-8 in the #Strings heap
        $ns       = { 51 51 E5 BE A9 E8 A4 87 E8 A6 86 }
        $asm_name = "dnqK.exe" ascii

    condition:
        uint16(0) == 0x5A4D
        and dotnet.is_dotnet
        and filesize < 2MB
        and (
            $xor_key
            or (
                $ns and $asm_name
                and for any s in pe.sections : (
                    s.name == ".text" and math.entropy(s.raw_data_offset, s.raw_data_size) > 7.5
                )
            )
        )
}

rule AgentTesla_Campaign_SMTP_Memory
{
    meta:
        description = "SMTP exfiltration settings of the albushrametalic campaign. Present only after decryption, so scan unpacked payloads or memory"
        author      = "Artful Dodger"
        date        = "2026-09-28"
        family      = "AgentTesla"
        reference   = "https://artfuldodger10.github.io/posts/AgentTesla-RAT-Full-Malware-Analysis-Report/"
        scope       = "memory, unpacked payload"

    strings:
        $host = "mail.albushrametalic.com" ascii wide nocase
        $user = "mustafa@albushrametalic.com" ascii wide nocase
        $to   = "saeed9797seead@gmail.com" ascii wide nocase
        $pass = "GLBL1285#" ascii wide

    condition:
        2 of them
}
