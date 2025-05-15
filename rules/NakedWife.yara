/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp2t_k3q_g
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule NakedWife {
   meta:
      description = "tmp2t_k3q_g - file NakedWife.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "29ceeb3d763d307a0dd7068fa1b2009f2b0d85ca6d2aa5867b12c595ba96762a"
   strings:
      $x1 = "A*\\AC:\\Documents and Settings\\mhsantos\\Desktop\\Temp\\ProjTemp\\ProjTemp.vbp" fullword wide /* score: '32.00'*/
      $s2 = "NakedWife.exe" fullword wide /* score: '22.00'*/
      $s3 = "Scripting.FileSystemObject" fullword wide /* PEStudio Blacklist: strings */ /* score: '18.00'*/
      $s4 = "\\*.exe" fullword wide /* score: '13.00'*/
      $s5 = "\\*.com" fullword wide /* score: '12.00'*/
      $s6 = "GetSpecialFolder" fullword wide /* score: '9.00'*/
      $s7 = "AddressLists" fullword wide /* score: '7.00'*/
      $s8 = "AddressEntries" fullword wide /* score: '7.00'*/
      $s9 = "mnuLine5" fullword ascii /* score: '5.00'*/
      $s10 = "mnuZoom100" fullword ascii /* score: '5.00'*/
      $s11 = "mnuLine1" fullword ascii /* score: '5.00'*/
      $s12 = "mnuLine2" fullword ascii /* score: '5.00'*/
      $s13 = "mnuLine6" fullword ascii /* score: '5.00'*/
      $s14 = "mnuLine4" fullword ascii /* score: '5.00'*/
      $s15 = "mnuLine3" fullword ascii /* score: '5.00'*/
      $s16 = "Full Screen" fullword ascii /* score: '4.00'*/
      $s17 = "Show &All" fullword ascii /* score: '4.00'*/
      $s18 = "mnuCreateProj" fullword ascii /* score: '4.00'*/
      $s19 = "mnuControl" fullword ascii /* score: '4.00'*/
      $s20 = "&Quality" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      1 of ($x*) and 4 of them
}

