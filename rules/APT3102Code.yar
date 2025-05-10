rule APT3102Code
{

    meta:
        description = "3102 code features"
    strings:
        $setupthread = { B9 02 07 00 00 BE ?? ?? ?? ?? 8B F8 6A 00 F3 A5 }

    condition:
        any of them
}