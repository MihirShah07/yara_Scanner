/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpyvz0ug_0
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpyvz0ug_0_satan {
   meta:
      description = "tmpyvz0ug_0 - file satan.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "1a0a2fd546e3c05e15b2db3b531cb8e8755641f5f1c17910ce2fb7bbce2a05b7"
   strings:
      $s1 = "d41a78af893bea5fe4c8dc019ef312965b0eb88064d77f01e16d47cfcf0c5de9e50deb2223166ad7ec648ad34c6218bd825768f05153fc45b861031c28afa3ab" ascii /* score: '11.00'*/
      $s2 = "616f7e48eb658762e8c3f6b68a34b74e50519013f589172eead6c2f1fc8f922b35a9e3c3edc57d4ec89ae264da941e0742ba4c8026076b0d0d5bc1e75b468a66" ascii /* score: '11.00'*/
      $s3 = "dd4b3ffb8c963cfe69535481b2664ec6f35138847e7c97fe3b230d32a7b6dc40a40e19ed04daf9aff5012da3a6bdaf2c739c28dd35c57eee0a26187bd552fec3" ascii /* score: '11.00'*/
      $s4 = "2750ff08a80528df4ef37eb22febb12cd5722da59cc0f190bf120b558ce9a28fb909b09f7fbf3df6951dd2e2ad64b14fa271066ea9827b9125ac38556f85ac77" ascii /* score: '11.00'*/
      $s5 = "37f8f2e0de94919e6e689a0294a6c00865357ec84752eaaef822e9215a82956bfa5e3095a229340a2df5a4cb7e6360be8d703727da338d790cbbf5ccb8aa46f3" ascii /* score: '11.00'*/
      $s6 = "69b5d7652a3ce021ec0e5244547fcdbed471f7a696e90e6301f4963b1353e931ed05b9e94c707714a8b9efd7d139d95a59c5cbe71f1e2915a524917bc9ed6c9b" ascii /* score: '11.00'*/
      $s7 = "29703c04c1516899a915f00defcb90940e53a904b31f2d7cd61330fb6dcb0d2b77d7b1706f85f2694f94a6f8031d27d2f484e6313ce9b15ab9dc531cfc96100e" ascii /* score: '11.00'*/
      $s8 = "f9f312169e7be2ba0a7446afb1614be80dc62c122142d164796033ff31e0600b58246a9881d15f323369e5db73c67b13fe47e48e0759133047cedb2a5c09b776" ascii /* score: '11.00'*/
      $s9 = "f7cdda428d5c837b3c91cc5e1fdb6559282c92bb49d1003e130aa5fd52e1ac919b541021a67c52323d590a6d2cce9ce53a81bcb40f8a8c19a3b26e849c6a72ab" ascii /* score: '11.00'*/
      $s10 = "7f41edd0beff7ad5b4af8b614142edc2afe2552e824b2d97b1c5697a10b54be931c0f406c470bbf309b1ff55e0d366569224019d07628a3f3e7553328ece6665" ascii /* score: '11.00'*/
      $s11 = "36f4100b77bf8257de0b1362072dded196e2b9e287eb01f0f727635733199d872ebf651cdc46888151feb163563212dc5c70ead75fe658f89cef028ba7bd4e32" ascii /* score: '11.00'*/
      $s12 = "db63e8b5213116787de9799bf194f2828d2c6bac9946f746471a13c7fd81bcbde9a10e8c56ee78148d3931a626355d302452bb55d48321986a05a86899192c8c" ascii /* score: '11.00'*/
      $s13 = "3d10ebfb9a71e64818f845c4260a743711d879c4e3514ef97f083c1589b34559f262fd9ae79c4f37be90d6321f68c4df86a891d1d237eb60eb1016d68d75749c" ascii /* score: '11.00'*/
      $s14 = "25600e819bac4ddfbf243781c051138dc54fbc9d5381b236136b45378f72b0757faff735e6cf07aeac1a84bfb36dd5f5efdc6e48ba304c68ccbc0ea9b403a359" ascii /* score: '11.00'*/
      $s15 = "164292ea3d12ec12d5aa27fdaefabc088b761ea0abe949c420a04f927370aec5f7bfebf7b46c773d6142056a67b8438ccc8f35f8a1939363ef524ffd4828c15c" ascii /* score: '11.00'*/
      $s16 = "ce024a3d63301d6e3f1fd21ed729367dda469710e4a11b6b2d9a1d892a1d2422732d3e35e9100057f643bac1d570a2be947da0d3600cd932efdfcc08e0b05ec1" ascii /* score: '11.00'*/
      $s17 = "cb6a236914ebd83d20815a7adc8151ab5f8fcefcb5de8889cfbd9d8e4a3f1f3d9b25611ee196dc93554c74fd9852bb45767333ec6ddffbe4621445811438e599" ascii /* score: '11.00'*/
      $s18 = "ae9bbdde31d7d0b09a668b7a2b29ada5451fde2f7ed0f075e44370aed2dd9a4005c3c45f4f7b3b3e998f63566f49aee798adee69d290f22d28343b7fb486ce7b" ascii /* score: '11.00'*/
      $s19 = "92b21a8b30c9cea6f28b57e86969af317f079403afd97549c8b8d20516e7b4f1fb5469acbc71435754392bc9e3488ec42472ec1afb0559ba8c289afd2b18eefa" ascii /* score: '11.00'*/
      $s20 = "59a7e49820e8543fc08963a1cc3a99b70f20065c385e5d4fcbc2b6fbaaf8ce92d8105f044298febd56291d33e80127b02eb03c50fc4bb7ac3e89478eb9d92d6c" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      8 of them
}

