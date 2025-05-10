rule ccrewQAZ
{

    meta:
        author = "cyrus"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $a = "!QAZ@WSX" wide ascii

  condition:
        $a
}
