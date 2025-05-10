rule Elise
{

    meta:
        author = "cyrus"
        info = "CommentCrew-threat-apt1"
       
    strings:
        $a = "SetElise.pdb" wide ascii

    condition:
        $a
}