/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp3fftompg
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmp3fftompg_Ana {
   meta:
      description = "tmp3fftompg - file Ana.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "117d7af0deb40b3fe532bb6cbe374884fa55ed7cfe053fe698720cdccb5a59cb"
   strings:
      $x1 = "C:\\Users\\DarkCoderSc\\Desktop\\Celesty Binder\\Stub\\STATIC\\Stub.pdb" fullword ascii /* score: '39.00'*/
      $x2 = "d0foqXZaQ2sUVrhiGnmO0UimsWAF+bw3TdoxwAccHxDwRa3BkW9yYfN89IDCu9a4Mr0ADqLUSU+AWTwYhUN7KzuR2MRiFs6Ua8nHDNkXWEb6VUbPLav5SiD+CZ3m3ZJp" ascii /* score: '33.00'*/
      $x3 = "KkOSMQbkqSPZ0LPVZxogC+nW34E/Mm05UydOPqGEg+++HlAcJ/sFLrPHJkn95Zd468t2Nogg4GIxM39/I2GgnRwc72s4H7Pw6DxVnYHzTF5JoprSzHYlQvnxgHTIH8rl" ascii /* score: '33.00'*/
      $x4 = "Worm:Win32/Conficker.B is a worm that infects other computers across a network by exploiting a vulnerability in the Windows Serv" wide /* score: '31.00'*/
      $s5 = "hSystem.Drawing.Bitmap, System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADZ" fullword ascii /* score: '27.00'*/
      $s6 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s7 = "fSystem.Drawing.Icon, System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap, S" ascii /* score: '27.00'*/
      $s8 = "fSystem.Drawing.Icon, System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap, S" ascii /* score: '27.00'*/
      $s9 = "hSystem.Drawing.Bitmap, System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD%" fullword ascii /* score: '27.00'*/
      $s10 = "processHead.gif" fullword wide /* score: '26.00'*/
      $s11 = "UvYYZZft9rqoqqz8QHNxTy3K7CcJVw3/KmrLr8I4X5Fw2/FlVWVTsbjQXxjFUzcZapDJTXMVImT1d1um8gKMoYwnc4kOZcMNEbYIpnt6xJjtgQacb4B+64EAf8TJq/sj" ascii /* score: '25.00'*/
      $s12 = "RtlDriver32.exe" fullword wide /* score: '25.00'*/
      $s13 = "ystem.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPy" fullword ascii /* score: '24.00'*/
      $s14 = "/F /IM explorer.exe" fullword wide /* score: '23.00'*/
      $s15 = "VCC+4UPGyGBU6kVM1pvmvFXtURFS3lWi3QlCj82XitmiLCCQyg2/zrjOcXkSUE7JsPU2K8+PZWHiEi0s038pkaRG3MmoCB/OtaHW1GguqcOi/5N8M5oa2X7BqSgqs4pb" ascii /* score: '21.00'*/
      $s16 = "Virus:Win32/Virut.BN is a detection for a polymorphic file infector that targets .EXE and .SCR Windows files." fullword wide /* score: '21.00'*/
      $s17 = "Test.COM" fullword wide /* score: '21.00'*/
      $s18 = "Ra4hd0IHzZdlLyRtUUPHQM9tb3eKm4FmS36+ctNQE6MEPWazigSM0SKwtaUGffpkwFx2e7uijiBIIOrbsRgfkpk6QPzgAmz+4DoLI9uTHni8+PHvZuGLE/S5za2oOsL9" ascii /* score: '20.00'*/
      $s19 = "http://report.totalsolutionantivirus.com/installs" fullword wide /* score: '20.00'*/
      $s20 = "gnircUMGHcs+g2I+yBNhEy0B1xtZ+qcSryjz4bvjBmXgU1Dc937vwwbU6VRDM9SKqMIeh2pvUo03nrVStwoYr23V67oD+OCx4zI5M6qaRtObgvBaAaMhlqZRuN2QYNAG" ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      1 of ($x*) and 4 of them
}

