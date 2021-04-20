// Copyright (C) 2020 Hatching B.V.
// All rights reserved.

rule family_qnodeservice{
    meta:
    	author = "Ramazan 'taitlex' Uysal"
        short_description = "QNodeService NodeJS Trojan"
        description = "A trojan written in NodeJS and spread via Java downloader. Utilizes stealer functionality."
    	family = "qnodeservice"
        tags = "trojan,backdoor"
    	score = 10

    strings:
    	$wizard1 = "escapeParameterWindows"
        $wizard2 = "downloadFile"
        $wizard3 = "qnodejs-wizard-lock"

        $qnodejs1 = "info/get-user-home"
        $qnodejs2 = "qnode-service"
        $qnodejs3 = "machine-uuid"
        $qnodejs4 = "identifierInformation"

        $encoded1 = "IWZ1bmN0aW9uKGUpe3ZhciB"
        $encoded2 = "cnRzPXJlcXVpc"
        $encoded3 = "pfWNvbnN0IGo9KCgpPT57c3dpdGN"
        $encoded4 = "dyBuZXcgRXJy"

    condition:
    	(all of ($wizard*)) or (all of ($qnodejs*)) or (all of ($encoded*))
}
