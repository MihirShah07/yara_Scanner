rule Carbanak_0915_3
{

    meta:
        description = "Carbanak Malware"
        author = "cyrus"
        reference = "https://www.csis.dk/en/csis/blog/4710/"
        score = 70

    strings:
        $s1 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii
        $s2 = "SHInvokePrinterCommandA" fullword ascii
        $s3 = "Ycwxnkaj" fullword ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 700KB and all of them
}
