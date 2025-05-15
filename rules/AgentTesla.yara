/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp5moqp1x6
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule AgentTesla {
   meta:
      description = "tmp5moqp1x6 - file AgentTesla.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "18aab0e981eee9e4ef8e15d4b003b14b3a1b0bfb7233fade8ee4b6a22a5abbb9"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '46.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>Nu" ascii /* score: '31.00'*/
      $s3 = "ntrols\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></dependentAssembl" ascii /* score: '25.00'*/
      $s4 = "dency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"requ" ascii /* score: '22.00'*/
      $s5 = "%s%S.dll" fullword wide /* score: '21.00'*/
      $s6 = "nstall System v3.05</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s7 = "WcLM:\\" fullword ascii /* score: '10.00'*/
      $s8 = "Administrator\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-co" ascii /* score: '10.00'*/
      $s9 = ";* -^|I`V2z" fullword ascii /* score: '9.00'*/
      $s10 = "CRYPTBASE" fullword ascii /* score: '8.50'*/
      $s11 = "6IF\\* %d " fullword ascii /* score: '8.00'*/
      $s12 = "-83d0f6d0da78}\"/><supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/><supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a244022" ascii /* score: '7.00'*/
      $s13 = "mC:\"*Y" fullword ascii /* score: '7.00'*/
      $s14 = "PROPSYS" fullword ascii /* score: '6.50'*/
      $s15 = "NTMARTA" fullword ascii /* score: '6.50'*/
      $s16 = "UXTHEME" fullword ascii /* score: '6.50'*/
      $s17 = "APPHELP" fullword ascii /* score: '6.50'*/
      $s18 = "\\+ k1#" fullword ascii /* score: '6.00'*/
      $s19 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '6.00'*/
      $s20 = ".6@tlog" fullword ascii /* score: '6.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 9000KB and
      1 of ($x*) and 4 of them
}

