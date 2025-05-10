rule APT3102Strings
{
    
    meta:
        description = "3102 Identifying Strings"

    strings:
        $ = "rundll32_exec.dll\x00Update"

    condition:
       any of them
}
