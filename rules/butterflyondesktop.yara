/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpqshr2cul
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule butterflyondesktop {
   meta:
      description = "tmpqshr2cul - file butterflyondesktop.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "4641af6a0071e11e13ad3b1cd950e01300542c2b9efb6ae92ffecedde974a4a6"
   strings:
      $s1 = "            <requestedExecutionLevel level=\"asInvoker\"            uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s2 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii /* score: '12.00'*/
      $s3 = "    processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s4 = "OCWdT.wwe" fullword ascii /* score: '10.00'*/
      $s5 = "            processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s6 = "            publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* score: '8.00'*/
      $s7 = "            version=\"6.0.0.0\"" fullword ascii /* score: '7.00'*/
      $s8 = "#oZ:\"6" fullword ascii /* score: '7.00'*/
      $s9 = "d:\"44=&" fullword ascii /* score: '7.00'*/
      $s10 = "    version=\"1.0.0.0\"" fullword ascii /* score: '7.00'*/
      $s11 = "            name=\"Microsoft.Windows.Common-Controls\"" fullword ascii /* score: '6.00'*/
      $s12 = "Z9-E{V -" fullword ascii /* score: '5.00'*/
      $s13 = "erhnmy" fullword ascii /* score: '5.00'*/
      $s14 = "n%FfD%\">" fullword ascii /* score: '5.00'*/
      $s15 = "qprioj" fullword ascii /* score: '5.00'*/
      $s16 = "*O+ *e" fullword ascii /* score: '5.00'*/
      $s17 = "b_*e)Dc+ " fullword ascii /* score: '5.00'*/
      $s18 = "(q2d* ]" fullword ascii /* score: '5.00'*/
      $s19 = "{~\\ /eZ" fullword ascii /* score: '5.00'*/
      $s20 = "pnqpry" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 9000KB and
      8 of them
}

