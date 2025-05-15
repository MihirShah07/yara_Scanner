/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpp6c7c4qf
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpp6c7c4qf_Heap41A {
   meta:
      description = "tmpp6c7c4qf - file Heap41A.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "746153871f816ece357589b2351818e449b1beecfb21eb75a3305899ce9ae37c"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?> <assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersi" ascii /* score: '32.00'*/
      $s2 = "s\" version=\"6.0.0.0\" processorArchitecture=\"X86\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /> </dependentAssembly>" ascii /* score: '25.00'*/
      $s3 = "MicrosoftPowerPoint\\svchost.exe" fullword ascii /* score: '25.00'*/
      $s4 = "> <assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Roshal.WinRAR.WinRAR\" type=\"win32\" /> <descripti" ascii /* score: '22.00'*/
      $s5 = "Cannot create folder %s6CRC failed in the encrypted file %s (wrong password ?)" fullword wide /* score: '19.00'*/
      $s6 = "GETPASSWORD1" fullword ascii /* score: '18.00'*/
      $s7 = "Wrong password for %s5Write error in the file %s. Probably the disk is full" fullword wide /* score: '18.00'*/
      $s8 = "4444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444" ascii /* score: '17.00'*/ /* hex encoded string 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD' */
      $s9 = "733333333333333333333330" ascii /* score: '17.00'*/ /* hex encoded string 's33333333330' */
      $s10 = "<head><meta http-equiv=\"content-type\" content=\"text/html; charset=" fullword ascii /* score: '17.00'*/
      $s11 = "44444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444" ascii /* score: '17.00'*/ /* hex encoded string 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD' */
      $s12 = "&Enter password for the encrypted file:" fullword wide /* score: '17.00'*/
      $s13 = "MicrosoftPowerPoint\\drivelist.txt" fullword ascii /* score: '16.00'*/
      $s14 = "MicrosoftPowerPoint\\pathlist.txt" fullword ascii /* score: '16.00'*/
      $s15 = "MicrosoftPowerPoint\\Install.txt" fullword ascii /* score: '16.00'*/
      $s16 = "%s.%d.tmp" fullword ascii /* score: '14.00'*/
      $s17 = "R archiver.</description> <dependency> <dependentAssembly> <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Cont" ascii /* score: '13.00'*/
      $s18 = "MicrosoftPowerPoint\\Icon.ico" fullword ascii /* score: '12.00'*/
      $s19 = "ErroraErrors encountered while performing the operation" fullword wide /* score: '12.00'*/
      $s20 = "TempMode" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

