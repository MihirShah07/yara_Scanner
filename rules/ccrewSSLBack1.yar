rule ccrewSSLBack1
{

    meta:
        author = "cyrus"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $a = "!@#%$^#@!" wide ascii
        $b = "64.91.80.6" wide ascii

  condition:
        any of them
}