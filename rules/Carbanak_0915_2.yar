rule Carbanak_0915_2
{

    meta:
        description = "Carbanak Malware"
        author = "cyrus"
        reference = "https://www.csis.dk/en/csis/blog/4710/"
        score = 70

    strings:
        $x1 = "8Rkzy.exe" fullword wide
        $s1 = "Export Template" fullword wide
        $s2 = "Session folder with name '%s' already exists." fullword ascii
        $s3 = "Show Unconnected Endpoints (Ctrl+U)" fullword ascii
        $s4 = "Close All Documents" fullword wide
        $s5 = "Add &Resource" fullword ascii
        $s6 = "PROCEXPLORER" fullword wide /* Goodware String - occured 1 times */
        $s7 = "AssocQueryKeyA" fullword ascii /* Goodware String - occured 4 times */
    condition:
        uint16(0) == 0x5a4d and filesize < 500KB and ( $x1 or all of ($s*) )
}