import "pe"

rule Shamoon2_Wiper {
   meta:
      description = "Detects Shamoon 2.0 Wiper Component"
      author = "Florian Roth"
      reference = "https://goo.gl/jKIfGB"
      date = "2016-12-01"
      score = 70
      hash1 = "c7fc1f9c2bed748b50a599ee2fa609eb7c9ddaeb9cd16633ba0d10cf66891d8a"
      hash2 = "128fa5815c6fee68463b18051c1a1ccdf28c599ce321691686b1efa4838a2acd"
   strings:
      $a1 = "\\??\\%s\\System32\\%s.exe" fullword wide
      $x1 = "IWHBWWHVCIDBRAFUASIIWURRTWRTIBIVJDGWTRRREFDEAEBIAEBJGGCSVUHGVJUHADIEWAFGWADRUWDTJBHTSITDVVBCIDCWHRHVTDVCDESTHWSUAEHGTWTJWFIRTBRB" wide
      $s1 = "UFWYNYNTS" fullword wide
      $s2 = "\\\\?\\ElRawDisk" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and 2 of them ) or ( 3 of them )
}

rule EldoS_RawDisk {
   meta:
      description = "EldoS Rawdisk Device Driver (Commercial raw disk access driver - used in Operation Shamoon 2.0)"
      author = "Florian Roth (with Binar.ly)"
      reference = "https://goo.gl/jKIfGB"
      date = "2016-12-01"
      score = 50
      hash1 = "47bb36cd2832a18b5ae951cf5a7d44fba6d8f5dca0a372392d40f51d1fe1ac34"
      hash2 = "394a7ebad5dfc13d6c75945a61063470dc3b68f7a207613b79ef000e1990909b"
   strings:
      $s1 = "g\\system32\\" fullword wide
      $s2 = "ztvttw" fullword wide
      $s3 = "lwizvm" fullword ascii
      $s4 = "FEJIKC" fullword ascii
      $s5 = "INZQND" fullword ascii
      $s6 = "IUTLOM" fullword wide
      $s7 = "DKFKCK" fullword ascii

      $op1 = { 94 35 77 73 03 40 eb e9 }
      $op2 = { 80 7c 41 01 00 74 0a 3d }
      $op3 = { 74 0a 3d 00 94 35 77 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and 4 of them )
}

rule Detect_EventLogTampering: AntiForensic {
    meta: 
        description = "Detect NtLoadDriver and other as anti-forensic"
        author = "Unprotect"
        comment = "Experimental rule"
    strings:
        $1 = "NtLoadDriver " fullword ascii
        $2 = "NdrClientCall2" fullword ascii
    condition:   
       uint16(0) == 0x5A4D and filesize < 1000KB and any of them 
}
