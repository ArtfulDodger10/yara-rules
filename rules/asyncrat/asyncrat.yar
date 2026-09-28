/*
    AsyncRAT detections
    Nader Ayman (Artful Dodger)

    AsyncRAT_Payload_Generic         family rule for the .NET client
    AsyncRAT_Campaign_xTeam_Memory   config of the xTeam build, decrypted in memory only
*/

import "dotnet"

rule AsyncRAT_Payload_Generic
{
    meta:
        description = "AsyncRAT client: PBKDF2/AES/HMAC config crypto, SslStream C2, and its anti-analysis and persistence strings"
        author      = "Nader Ayman (Artful Dodger)"
        date        = "2026-09-28"
        family      = "AsyncRAT"
        hash        = "3dbaf616dcaacfcf66909b7a3404d1536f9e0d230b3b59934f1ccc6fe3e20554"
        note        = "Framework type and P/Invoke names survive renaming obfuscators, so the core of the rule rests on them"

    strings:
        // framework types in the #Strings heap
        $crypto1  = "AesCryptoServiceProvider" ascii
        $crypto2  = "Rfc2898DeriveBytes" ascii
        $crypto3  = "HMACSHA256" ascii
        $net1     = "SslStream" ascii
        $net2     = "AuthenticateAsClient" ascii
        $net3     = "TcpClient" ascii

        // P/Invoke imports
        $critical = "RtlSetProcessIsCritical" ascii
        $debugger = "CheckRemoteDebuggerPresent" ascii

        // user strings
        $persist  = "schtasks /create /f /sc onlogon /rl highest" ascii wide
        $sandbox  = "SbieDll.dll" ascii wide
        $vm       = "VirtualBox" ascii wide
        $av1      = "Select * from AntivirusProduct" ascii wide nocase
        $av2      = "\\root\\SecurityCenter2" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D
        and dotnet.is_dotnet
        and filesize < 1MB
        and all of ($crypto*)
        and all of ($net*)
        and 1 of ($critical, $debugger)
        and 2 of ($persist, $sandbox, $vm, $av*)
}

rule AsyncRAT_Campaign_xTeam_Memory
{
    meta:
        description = "Config values of the xTeam AsyncRAT 0.5.8 build. The config is AES-encrypted on disk, so scan memory or a decrypted dump"
        author      = "Nader Ayman (Artful Dodger)"
        date        = "2026-09-28"
        family      = "AsyncRAT"
        scope       = "memory"
        reference   = "https://app.any.run/tasks/2fa8f14b-f2ac-45d4-9b72-18e1f595e383"

    strings:
        $c2      = "hubscore.io" ascii wide nocase
        $mutex   = "rxUf9crL1mff" ascii wide
        $install = "c2.skyupdragon.io.exe" ascii wide nocase

    condition:
        2 of them
}
