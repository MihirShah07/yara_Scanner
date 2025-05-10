rule Casper_Included_Strings
{

    meta:
        description = "Casper French Espionage Malware - String Match in File - http://goo.gl/VRJNLo"
        author = "cyrus"
        reference = "http://goo.gl/VRJNLo"
        score = 50

    strings:
        $a0 = "cmd.exe /C FOR /L %%i IN (1,1,%d) DO IF EXIST"
        $a1 = "& SYSTEMINFO) ELSE EXIT"
        $mz = { 4d 5a }
        $c1 = "domcommon.exe" wide fullword                         // File Name
        $c2 = "jpic.gov.sy" fullword                                // C2 Server
        $c3 = "aiomgr.exe" wide fullword                            // File Name
        $c4 = "perfaudio.dat" fullword                              // Temp File Name
        $c5 = "Casper_DLL.dll" fullword                             // Name
        $c6 = { 7B 4B 59 DE 37 4A 42 26 59 98 63 C6 2D 0F 57 40 }   // Decryption Key
        $c7 = "{4216567A-4512-9825-7745F856}" fullword              // Mutex

    condition:
        all of ($a*) or ( $mz at 0 ) and ( 1 of ($c*) )
}