rule ccrewSSLBack3
{

    meta:
        author = "cyrus"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $a = "SLYHKAAY" wide ascii

  condition:
        any of them
}
