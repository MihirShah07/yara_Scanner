rule FE_APT_9002
{
    
    meta:
        Description = "Strings inside"
        Reference   = "Useful link"
        
    strings:
        $mz = { 4d 5a }
        $a = "rat_UnInstall" wide ascii

    condition:
        ($mz at 0) and $a
}
