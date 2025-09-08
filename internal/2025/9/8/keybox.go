package widevine

import (
   "bytes"
   "crypto/aes"
   "crypto/cipher"
   "encoding/hex"
   "errors"
   "log"
)

const (
   stage0 = "MSTAR_SECURE_STORE_FILE_MAGIC_ID"
   // some files do not have this even with correct key, instead:
   // strip first 64 bytes, and then the next 32 bytes is your zgpriv
   stage1 = "INNER_MSTAR_FILE"
)

var keys = []struct {
   value string
   note  string
}{
   {
      value: "0007FF4154534D92FC55AA0FFF0110E0",
      note:  "Master Key MSTAR",
   },
   {
      value: "24490B4CC95F739CE34138478E47139E",
      note:  "advised by lossui (not sure when to be used)",
   },
   {
      value: "BC1197CA30AA0FC84F7FE62E09FD3D9F",
      note:  "Master Key Hisense",
   },
   {
      value: "8981D083B3D53B3DF1AC529A70F244C0",
      note:  "Master Key Vestel",
   },
   {
      value: "3503B1CDE3401EC06030C12A4311F4A5",
      note:  "Master Key KTC",
   },
   {
      value: "E33AB4C45C2570B8AD15A921F752DEB6",
      note:  "Master Key LG",
   },
   {
      value: "206955BFC5F0FAF84396C2379237AC08",
      note:  "in many older dumps (not sure if usable)",
   },
   {
      value: "B9C956919B48E1671564F4CADB5FE63C",
      note:  "Skyworth",
   },
   {
      value: "F8686BF589D42AE2ABD019775A541420",
      note:  "AOC/TPV",
   },
}

func DecryptAes128Ecb(data, key []byte) []byte {
   cipher, _ := aes.NewCipher(key)
   decrypted := make([]byte, len(data))
   size := 16
   for lo, hi := 0, size; lo < len(data); lo, hi = lo+size, hi+size {
      cipher.Decrypt(decrypted[lo:hi], data[lo:hi])
   }
   return decrypted
}

func ecb(data []byte) error {
   for i := range data {
      value := data[i:]
      if len(value)%16 == 0 {
         for _, raw_key := range keys {
            key, err := hex.DecodeString(raw_key.value)
            if err != nil {
               return err
            }
            dest := DecryptAes128Ecb(value, key)
            if bytes.Contains(dest, []byte(stage1)) {
               log.Println("ECB", i, raw_key.value)
               return nil
            }
         }
      }
   }
   return errors.New("ECB")
}

func cbc(data []byte) error {
   data1 := make([]byte, len(data))
   var iv [16]byte
   for i := range data {
      value := data[i:]
      if len(value)%16 == 0 {
         for _, raw_key := range keys {
            key, err := hex.DecodeString(raw_key.value)
            if err != nil {
               return err
            }
            block, err := aes.NewCipher(key)
            if err != nil {
               return err
            }
            cipher.NewCBCDecrypter(block, iv[:]).CryptBlocks(data1, value)
            if bytes.Contains(data1, []byte(stage1)) {
               log.Println("CBC", i, raw_key.value)
               return nil
            }
         }
      }
   }
   return errors.New("CBC")
}

func ctr(data []byte) error {
   data1 := make([]byte, len(data))
   var iv [16]byte
   for i := range data {
      value := data[i:]
      if len(value)%16 == 0 {
         for _, raw_key := range keys {
            key, err := hex.DecodeString(raw_key.value)
            if err != nil {
               return err
            }
            block, err := aes.NewCipher(key)
            if err != nil {
               return err
            }
            cipher.NewCTR(block, iv[:]).XORKeyStream(data1, value)
            if bytes.Contains(data1, []byte(stage1)) {
               log.Println("CTR", i, raw_key.value)
               return nil
            }
         }
      }
   }
   return errors.New("CTR")
}
