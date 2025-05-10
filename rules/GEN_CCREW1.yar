rule GEN_CCREW1
{

    meta:
        author = "cyrus"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $a = "W!r@o#n$g" wide ascii
        $b = "KerNel32.dll" wide ascii

    condition:
        any of them
}