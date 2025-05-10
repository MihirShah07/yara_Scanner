rule APT1_WEBC2_ADSPACE
{

    meta:
        author = "cyrus"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $1 = "<!---HEADER ADSPACE style=" wide ascii
        $2 = "ERSVC.DLL" wide ascii

    condition:
        all of them
}