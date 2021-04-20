// Copyright (C) 2020 Hatching B.V.
// All rights reserved.

rule sliverRAT {
    meta:
        short_description = "Sliver RAT"
        url = "https://github.com/BishopFox/sliver"
        author = "Brae"
        score = 10
        family = "sliver"
        tags = "trojan"

    strings:
        $pe = { 4D 5A }
        $sliver_root = "/root/.sliver/slivers/windows/amd64/"

    condition:
        ($pe at 0) and $sliver_root
}
