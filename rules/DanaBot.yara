/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpckxobjzp
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpckxobjzp_DanaBot {
   meta:
      description = "tmpckxobjzp - file DanaBot.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "db0d72bc7d10209f7fa354ec100d57abbb9fe2e57ce72789f5f88257c5d3ebd1"
   strings:
      $s1 = "buzuwuzaji.exe" fullword ascii /* score: '22.00'*/
      $s2 = " Type Descriptor'" fullword ascii /* score: '10.00'*/
      $s3 = "Povaloya juluzireyehuj\\Matafavosiy xazo janelagunevuvo yuli fepotazikokakav tuketeselogelot kakulenavik kizetudijaznHumacabuzun" wide /* score: '10.00'*/
      $s4 = "FaKe\"k" fullword ascii /* score: '9.00'*/
      $s5 = "Tisenewol bajizuc veyeloromas Jafuzojanufa puyova buzufovubusu" fullword wide /* score: '9.00'*/
      $s6 = "FubigawutojodiRDahohizal xipimejusunaso seka ruwibitugiwen leju koyozada wiwusagerebis litocopowiCDopak xilizirala vijojoj zaxes" wide /* score: '9.00'*/
      $s7 = "lllllpf" fullword ascii /* score: '8.00'*/
      $s8 = "jjjjjjjjjjjjjjj" fullword ascii /* score: '8.00'*/
      $s9 = "jjllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll" ascii /* score: '8.00'*/
      $s10 = "rHASh56" fullword ascii /* score: '8.00'*/
      $s11 = "jjllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll" ascii /* score: '8.00'*/
      $s12 = "jjjjjjjjjjjjjjz" fullword ascii /* score: '8.00'*/
      $s13 = "@plusTokenAfter@4" fullword ascii /* score: '7.00'*/
      $s14 = "<( I:\\" fullword ascii /* score: '7.00'*/
      $s15 = "I:\\r{V" fullword ascii /* score: '7.00'*/
      $s16 = "V:\"ogW=" fullword ascii /* score: '7.00'*/
      $s17 = "&(U:\\hO" fullword ascii /* score: '7.00'*/
      $s18 = "Nerakeyiti facepumajuh[Tapoy cowitosaxosa nixewesefix mumo cixiyumi boyidaxic gawececutahu tupuxasejaridin jecerig" fullword wide /* score: '7.00'*/
      $s19 = "E\"EyEk" fullword ascii /* score: '6.00'*/
      $s20 = "Ajjjjjjjjjjjjjj" fullword ascii /* score: '6.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      8 of them
}

