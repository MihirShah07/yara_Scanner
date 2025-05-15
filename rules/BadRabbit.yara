/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp3qt_b6jt
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule BadRabbit {
   meta:
      description = "tmp3qt_b6jt - file BadRabbit.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "630325cac09ac3fab908f903e3b00d0dadd5fdaa0875ed8496fcbb97a558d0da"
   strings:
      $s1 = "FlashUtil.exe" fullword wide /* score: '22.00'*/
      $s2 = "http://rb.symcb.com/rb.crt0" fullword ascii /* score: '17.00'*/
      $s3 = "https://d.symcb.com/rpa06" fullword ascii /* score: '17.00'*/
      $s4 = "C:\\Windows\\infpub.dat" fullword wide /* score: '17.00'*/
      $s5 = "(Symantec SHA256 TimeStamping Signer - G2" fullword ascii /* score: '15.00'*/
      $s6 = "(Symantec SHA256 TimeStamping Signer - G20" fullword ascii /* score: '15.00'*/
      $s7 = "http://s.symcd.com0" fullword ascii /* score: '14.00'*/
      $s8 = "http://rb.symcd.com0&" fullword ascii /* score: '14.00'*/
      $s9 = "infpub.dat" fullword wide /* score: '14.00'*/
      $s10 = "http://rb.symcb.com/rb.crl0W" fullword ascii /* score: '13.00'*/
      $s11 = "        <requestedExecutionLevel level=\"highestAvailable\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii /* score: '11.00'*/
      $s12 = ",Symantec Class 3 SHA256 Code Signing CA - G2" fullword ascii /* score: '10.00'*/
      $s13 = ",Symantec Class 3 SHA256 Code Signing CA - G20" fullword ascii /* score: '10.00'*/
      $s14 = "%ws C:\\Windows\\%ws,#1 %ws" fullword wide /* score: '10.00'*/
      $s15 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii /* score: '7.00'*/
      $s16 = " 1996-2017 Adobe Systems Incorporated" fullword wide /* score: '7.00'*/
      $s17 = "DDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPA" ascii /* score: '6.50'*/
      $s18 = " inflate 1.2.8 Copyright 1995-2013 Mark Adler " fullword ascii /* score: '6.00'*/
      $s19 = "%P%</vb" fullword ascii /* score: '5.00'*/
      $s20 = "\\lERi!" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

