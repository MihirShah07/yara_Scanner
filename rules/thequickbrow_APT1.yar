rule thequickbrow_APT1
{

    meta:
        author = "cyrus"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $s1 = "thequickbrownfxjmpsvalzydg" wide ascii

    condition:
        all of them
}
