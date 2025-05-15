/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp35_nvux2
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmp35_nvux2_Mabezat {
   meta:
      description = "tmp35_nvux2 - file Mabezat.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "2ae0c4a5f1fedf964e2f8a486bf0ee5d1816aac30c889458a9ac113d13b50ceb"
   strings:
      $s1 = "            processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s2 = "    processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s3 = "    name=\"Microsoft.Windows.COM.mobsync\"" fullword ascii /* score: '9.00'*/
      $s4 = "Synchronisatie voltooidFEr zijn fouten opgetreden tijdens het synchroniseren van uw gegevens. MEr zijn waarschuwingen opgetreden" wide /* score: '9.00'*/
      $s5 = "7Er is een onbekende fout opgetreden tijdens het bellen." fullword wide /* score: '9.00'*/
      $s6 = "            publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* score: '8.00'*/
      $s7 = "            version=\"6.0.0.0\"" fullword ascii /* score: '7.00'*/
      $s8 = "    version=\"5.1.0.0\"" fullword ascii /* score: '7.00'*/
      $s9 = "Om er zeker van te zijn dat u over de meest recente gegevens beschikt wanneer u off line werkt, kunt u de gegevens op de compute" wide /* score: '7.00'*/
      $s10 = "LAN-verbinding" fullword wide /* score: '7.00'*/
      $s11 = "Synchronisatiebeheer %d van de %d items zijn voltooid+Wilt u de huidige synchronisatie annuleren?FU kunt niet afsluiten omdat he" wide /* score: '7.00'*/
      $s12 = "NGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDI" ascii /* score: '6.50'*/
      $s13 = "PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDI" ascii /* score: '6.50'*/
      $s14 = "NGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" fullword ascii /* score: '6.50'*/
      $s15 = "            name=\"Microsoft.Windows.Common-Controls\"" fullword ascii /* score: '6.00'*/
      $s16 = "Synchronisatiefout" fullword wide /* score: '6.00'*/
      $s17 = "Bezig met synchroniseren:" fullword wide /* score: '4.00'*/
      $s18 = "Voortgang van synchronisatie" fullword wide /* score: '4.00'*/
      $s19 = "&Overslaan" fullword wide /* score: '4.00'*/
      $s20 = "Selecteer een item en klik op Overslaan als u dit onderdeel wilt overslaan." fullword wide /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

