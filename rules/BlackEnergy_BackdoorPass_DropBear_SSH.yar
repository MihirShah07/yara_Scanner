rule BlackEnergy_BackdoorPass_DropBear_SSH 
{
    
    meta:
        description = "Detects the password of the backdoored DropBear SSH Server - BlackEnergy"
        reference = "http://feedproxy.google.com/~r/eset/blog/~3/BXJbnGSvEFc/"
        hash = "0969daac4adc84ab7b50d4f9ffb16c4e1a07c6dbfc968bd6649497c794a161cd"
    
    strings:
        $s1 = "passDs5Bu9Te7" fullword ascii
    
    condition:
        uint16(0) == 0x5a4d and $s1
}
