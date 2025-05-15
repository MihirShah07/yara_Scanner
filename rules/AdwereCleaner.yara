/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpc8z_42b0
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule AdwereCleaner {
   meta:
      description = "tmpc8z_42b0 - file AdwereCleaner.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "51290129cccca38c6e3b4444d0dfb8d848c8f3fc2e5291fc0d219fd642530adc"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>Nu" ascii /* score: '31.00'*/
      $s3 = "nstall System v3.0a2</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requeste" ascii /* score: '16.00'*/
      $s4 = "xecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:sc" ascii /* score: '14.00'*/
      $s5 = "robert@jlflor.com0" fullword ascii /* score: '11.00'*/
      $s6 = "-microsoft-com:compatibility.v1\"><application><supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/><supportedOS Id=\"{4a" ascii /* score: '6.00'*/
      $s7 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '6.00'*/
      $s8 = "e3-53b9-4441-ba9c-d69d4a4a6e38}\"/><supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/></application></compatibility></a" ascii /* score: '6.00'*/
      $s9 = "q$+wB!." fullword ascii /* score: '5.00'*/
      $s10 = "hjfama" fullword ascii /* score: '5.00'*/
      $s11 = "vJVM)MW" fullword ascii /* score: '4.00'*/
      $s12 = "Zuid Holland1" fullword ascii /* score: '4.00'*/
      $s13 = "WAT Software Rotterdam0" fullword ascii /* score: '4.00'*/
      $s14 = "@xWApq!" fullword ascii /* score: '4.00'*/
      $s15 = "ttLaa9c\"" fullword ascii /* score: '4.00'*/
      $s16 = "DQsG?*" fullword ascii /* score: '4.00'*/
      $s17 = "bgJsw(+<3" fullword ascii /* score: '4.00'*/
      $s18 = "'Glhj{6K" fullword ascii /* score: '4.00'*/
      $s19 = "qibruuMl" fullword ascii /* score: '4.00'*/
      $s20 = "biulD/>" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      1 of ($x*) and 4 of them
}

