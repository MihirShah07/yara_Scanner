rule APT1_WEBC2_TABLE
{

    meta:
        author = "cyrus"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $msg1 = "Fail To Execute The Command" wide ascii
        $msg2 = "Execute The Command Successfully" wide ascii
        $gif2 = "GIF89" wide ascii

    condition:
        3 of them
}