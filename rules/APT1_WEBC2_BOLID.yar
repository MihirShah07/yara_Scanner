rule APT1_WEBC2_BOLID
{
    meta:
        author = "cyrus"
        info = "CommentCrew-threat-apt1"
      
    strings:
        $vm = "VMProtect" wide ascii
        $http = "http://[c2_location]/[page].html" wide ascii

    condition:
        all of them
}