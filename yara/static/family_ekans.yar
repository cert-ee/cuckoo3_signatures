// Copyright (C) 2020 Hatching B.V.
// All rights reserved.

import "pe"

rule family_ekans {
    meta:
        short_description = "Ekans Ransomware"
        description = "Executable looks like Ekans ICS ransomware sample."
        author = "Brae"
        family = "ekans"
        tags = "ransomware"
        score = 10

    strings:
        $pe = { 4D 5A }
        $re1 = /C:\/Users\/\w+\/go\/src\/[a-z]{20}\/[a-z]{20,22}\.go/ nocase
        $re1_1 = /C:\/Users\/\w+\/go\/src\/[a-z]{20}\/(misc|crypt)\.go/ nocase
        $re2 = /\*[a-z]{20}\.Cmd/ nocase

    condition:
        $pe at 0 and
        (#re1 > 5) or ($re1_1) and
        $re2 and
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name == ".symtab"
        )
 }
