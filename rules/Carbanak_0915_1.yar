rule Carbanak_0915_1
{

    meta:
        description = "Carbanak Malware"
        author = "cyrus"
        reference = "https://www.csis.dk/en/csis/blog/4710/"
        score = 70

    strings:
        $s1 = "evict1.pdb" fullword ascii
        $s2 = "http://testing.corp 0" fullword ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 100KB and 1 of them
}