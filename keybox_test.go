package widevine

import (
   "os"
   "testing"
)

func TestDecryptEcb(t *testing.T) {
   data, err := os.ReadFile("keyBox.bin")
   if err != nil {
      t.Fatal(err)
   }
   err = ecb(data)
   if err != nil {
      t.Fatal(err)
   }
}

func TestDecryptCbc(t *testing.T) {
   data, err := os.ReadFile("keyBox.bin")
   if err != nil {
      t.Fatal(err)
   }
   err = cbc(data)
   if err != nil {
      t.Fatal(err)
   }
}

func TestDecryptCtr(t *testing.T) {
   data, err := os.ReadFile("keyBox.bin")
   if err != nil {
      t.Fatal(err)
   }
   err = ctr(data)
   if err != nil {
      t.Fatal(err)
   }
}
