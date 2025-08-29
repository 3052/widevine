package widevine

import (
   "bytes"
   "crypto/aes"
   "crypto/cipher"
   "encoding/hex"
   "errors"
   "iter"
   "log"
)

var keys = []string{
   "0007FF4154534D92FC55AA0FFF0110E0", // default
   "24490B4CC95F739CE34138478E47139E", // advised by lossui (not sure when to be used)
   "BC1197CA30AA0FC84F7FE62E09FD3D9F", // Hisense
   "8981D083B3D53B3DF1AC529A70F244C0", // Vestel MB130
   "3503B1CDE3401EC06030C12A4311F4A5", // e.g. KTC
   "E33AB4C45C2570B8AD15A921F752DEB6", // LG
   "206955BFC5F0FAF84396C2379237AC08", // in many older dumps (not sure if usable)
   "B9C956919B48E1671564F4CADB5FE63C", // in some older dumps
   "F8686BF589D42AE2ABD019775A541420", // AOC/TPV
}

const (
   stage0 = "MSTAR_SECURE_STORE_FILE_MAGIC_ID"
   stage1 = "INNER_MSTAR_FILE"
)

func get_source(data []byte) iter.Seq[[]byte] {
   return func(yield func([]byte) bool) {
      for i := range data {
         if len(data[i:])%16 == 0 {
            log.Println("source", i)
            if !yield(data[i:]) {
               return
            }
         }
      }
   }
}

func cbc(data []byte) error {
   data1 := make([]byte, len(data))
   var iv [16]byte
   for source := range get_source(data) {
      for _, raw_key := range keys {
         key, err := hex.DecodeString(raw_key)
         if err != nil {
            return err
         }
         block, err := aes.NewCipher(key)
         if err != nil {
            return err
         }
         cipher.NewCBCDecrypter(block, iv[:]).CryptBlocks(data1, source)
         if bytes.Contains(data1, []byte(stage1)) {
            return nil
         }
      }
   }
   return errors.New("CBC")
}

func ctr(data []byte) error {
   data1 := make([]byte, len(data))
   var iv [16]byte
   for source := range get_source(data) {
      for _, raw_key := range keys {
         key, err := hex.DecodeString(raw_key)
         if err != nil {
            return err
         }
         block, err := aes.NewCipher(key)
         if err != nil {
            return err
         }
         cipher.NewCTR(block, iv[:]).XORKeyStream(data1, source)
         if bytes.Contains(data1, []byte(stage1)) {
            return nil
         }
      }
   }
   return errors.New("CTR")
}
