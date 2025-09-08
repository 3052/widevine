package widevine

import (
   "os"
   "testing"
)

const test_name = "zgpriv_protected.dat"

func TestDecryptEcb(t *testing.T) {
   data, err := os.ReadFile(test_name)
   if err != nil {
      t.Fatal(err)
   }
   err = ecb(data)
   if err != nil {
      t.Fatal(err)
   }
}

func TestDecryptCbc(t *testing.T) {
   data, err := os.ReadFile(test_name)
   if err != nil {
      t.Fatal(err)
   }
   err = cbc(data)
   if err != nil {
      t.Fatal(err)
   }
}

func TestDecryptCtr(t *testing.T) {
   data, err := os.ReadFile(test_name)
   if err != nil {
      t.Fatal(err)
   }
   err = ctr(data)
   if err != nil {
      t.Fatal(err)
   }
}
