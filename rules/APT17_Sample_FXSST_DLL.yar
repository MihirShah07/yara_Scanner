rule APT17_Sample_FXSST_DLL 
{
    
    meta:
        description = "Detects Samples related to APT17 activity - file FXSST.DLL"
        reference = "https://goo.gl/ZiJyQv"
        hash = "52f1add5ad28dc30f68afda5d41b354533d8bce3"
        
    strings:
        $x1 = "Microsoft? Windows? Operating System" fullword wide
        $x2 = "fxsst.dll" fullword ascii
        $y1 = "DllRegisterServer" fullword ascii
        $y2 = ".cSV" fullword ascii
        $s1 = "GetLastActivePopup"
        $s2 = "Sleep"
        $s3 = "GetModuleFileName"
        $s4 = "VirtualProtect"
        $s5 = "HeapAlloc"
        $s6 = "GetProcessHeap"
        $s7 = "GetCommandLine"
   
   condition:
        uint16(0) == 0x5a4d and filesize < 800KB and ( 1 of ($x*) or all of ($y*) ) and all of ($s*)
}
