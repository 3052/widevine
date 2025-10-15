package main

import (
   "41.neocities.org/drm/playReady"
   "flag"
   "log"
   "math/big"
   "os"
)

func (f *flag_set) ok() bool {
   if f.g1 != "" {
      if f.z1 != "" {
         return true
      }
   }
   return false
}

func write_file(name string, data []byte) error {
   log.Println("WriteFile", name)
   return os.WriteFile(name, data, os.ModePerm)
}

func main() {
   var set flag_set
   set.New()
   if set.ok() {
      err := set.do()
      if err != nil {
         panic(err)
      }
   } else {
      flag.Usage()
   }
}

type flag_set struct {
   encrypt_sign int64
   g1           string
   z1           string
}

func (f *flag_set) New() {
   flag.StringVar(&f.g1, "g", "", "g1")
   flag.StringVar(&f.z1, "z", "", "z1")
   flag.Int64Var(&f.encrypt_sign, "e", 1, "encrypt/sign")
   flag.Parse()
}

func (f *flag_set) do() error {
   data, err := os.ReadFile(f.g1)
   if err != nil {
      return err
   }
   var certificate playReady.Chain
   err = certificate.Decode(data)
   if err != nil {
      return err
   }
   data, err = os.ReadFile(f.z1)
   if err != nil {
      return err
   }
   z1 := new(big.Int).SetBytes(data)
   encryptSignKey := big.NewInt(f.encrypt_sign)
   err = certificate.Leaf(z1, encryptSignKey)
   if err != nil {
      return err
   }
   err = write_file("EncryptSignKey", encryptSignKey.Bytes())
   if err != nil {
      return err
   }
   return write_file("CertificateChain", certificate.Encode())
}
