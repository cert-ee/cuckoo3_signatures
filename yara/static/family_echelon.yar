// Copyright (C) 2020 Hatching B.V.
// All rights reserved

rule echelon {
    meta:
        author = "Brae"
        short_description = "Echelon Stealer"
        family = "echelon"
        tags = "stealer"
        score = 10

    strings:
        $s1 = "Echelon_Size" fullword ascii
        $s2 = "Echelon_Dir" fullword ascii
        $s3 = "GetStealer" ascii
        $s4 = "get_encryptedPassword" fullword ascii
        $s5 = "UnPackLibrary.exe" fullword ascii
        $s6 = "Echelon Stealer by @madcod" fullword wide ascii

        $pdb = "\\echelon stealer\\obj\\debug\\echelon.pdb" ascii wide nocase

    condition:
        uint16(0) == 0x5a4d and all of them
}

rule echelon_darkstealer {
    meta:
        author = "Brae"
        short_description = "Echelon - DarkStealer Fork"
        description = "Payload resembles modified variant of Echelon Stealer called DarkStealer."
        family = "darkstealer"
        tags = "stealer"
        score = 10

    strings:
        $s1 = "DarkStealer" ascii wide
        $s2 = "Echelon_Dir" ascii wide
        $s3 = "Newtonsoft.Json" ascii wide
        $s4 = "InfoHERE.html" fullword wide ascii

        $c1 = "Echelon.Stealer.Wallets" fullword ascii
        $c2 = "Echelon.Stealer.VPN" fullword ascii
        $c3 = "Echelon.Stealer.Telegram" fullword ascii
        $c4 = "Echelon.Stealer.Jabber" fullword ascii
        $c5 = "Echelon.Stealer.FTP" fullword ascii
        $c6 = "Echelon.Stealer.EmailClients" fullword ascii
        $c7 = "Echelon.Stealer.Discord" fullword ascii
        $c8 = "Echelon.Stealer.SystemsData" fullword ascii
        $c9 = "Echelon.Stealer.Grab" fullword ascii
        $c10 = "Echelon.Stealer.Browsers" fullword ascii

    condition:
        uint16(0) == 0x5a4d and all of them
}
