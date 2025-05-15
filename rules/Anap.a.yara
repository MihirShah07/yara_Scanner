/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpuu8d246c
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpuu8d246c_Anap_a {
   meta:
      description = "tmpuu8d246c - file Anap.a.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "da1798c0a49b991fbda674f02007b0a3be4703e2b07ee540539db7e5bf983278"
   strings:
      $s1 = "support@intel.com>" fullword ascii /* score: '17.00'*/
      $s2 = "support@ibm.com>" fullword ascii /* score: '17.00'*/
      $s3 = "support@pc.ibm.com>" fullword ascii /* score: '17.00'*/
      $s4 = "support@microsoft.com>" fullword ascii /* score: '17.00'*/
      $s5 = "Content-Disposition: attachment; filename=\"SETUP.EXE\"" fullword ascii /* score: '16.00'*/
      $s6 = "i-worm.Anaphylaxis coded by Bumblebee/29a" fullword ascii /* score: '16.00'*/
      $s7 = "support@netscape.com>" fullword ascii /* score: '13.00'*/
      $s8 = "Content-Type: application/octet-stream; name=\"SETUP.EXE\"" fullword ascii /* score: '12.00'*/
      $s9 = "worm has been infected by a virus during its travel and both arrived to " fullword ascii /* score: '11.00'*/
      $s10 = "Content-Type: text/plain; charset=us-ascii" fullword ascii /* score: '9.00'*/
      $s11 = "Content-Type: multipart/mixed; boundary=\"a1234\"" fullword ascii /* score: '9.00'*/
      $s12 = "Integrity check failed due to:" fullword ascii /* score: '7.00'*/
      $s13 = "Driver <" fullword ascii /* score: '7.00'*/
      $s14 = "8.EXEt" fullword ascii /* score: '5.00'*/
      $s15 = "mail from:" fullword ascii /* score: '4.00'*/
      $s16 = "Steel <" fullword ascii /* score: '4.00'*/
      $s17 = "Woodruf <" fullword ascii /* score: '4.00'*/
      $s18 = "rcpt to:" fullword ascii /* score: '4.00'*/
      $s19 = "Message-ID: <a1234>" fullword ascii /* score: '4.00'*/
      $s20 = "Forge <" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 50KB and
      8 of them
}

