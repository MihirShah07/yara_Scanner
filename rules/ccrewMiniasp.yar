rule ccrewMiniasp
{

    meta:
        author = "cyrus"
        info = "CommentCrew-threat-apt1"
        

  strings:
        $a = "MiniAsp.pdb" wide ascii
        $b = "device_t=" wide ascii

  condition:
        any of them
}