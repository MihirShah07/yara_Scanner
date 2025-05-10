rule metaxcd
{

    meta:
        author = "cyrus"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $a = "<meta xcd=" wide ascii

    condition:
        $a
}