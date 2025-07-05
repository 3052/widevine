package crc32

import (
   "encoding/binary"
   "encoding/hex"
   "os"
   "testing"
)

func Test1(t *testing.T) {
   data, err := hex.DecodeString("4852455f363638335f48414945524154565f6465765f303030303031303639329625a33df06b6e679c17a87739ac612a00000002000035c4a8398901ae37e0ae170bc56d0026a2b7b2ebf0dc37e0b6cc516cc93201ceb72bf39480312c0ab2a34edacf10361fb92c819f570c184d1627a06eebffb9cb07456b626f789308169d")
   if err != nil {
      t.Fatal(err)
   }
   calculatedCRC32 := calculateCRC32MPEG2(data[:124])
   expectedCRC32Val := binary.BigEndian.Uint32(data[124:])
   if calculatedCRC32 != expectedCRC32Val {
      t.Fatalf("%x", calculatedCRC32)
   }
}

func Test0(t *testing.T) {
   data, err := os.ReadFile("keybox.bin")
   if err != nil {
      t.Fatal(err)
   }
   calculatedCRC32 := calculateCRC32MPEG2(data[:124])
   expectedCRC32Val := binary.BigEndian.Uint32(data[124:])
   if calculatedCRC32 != expectedCRC32Val {
      t.Fatal("calculatedCRC32 != expectedCRC32Val")
   }
}
