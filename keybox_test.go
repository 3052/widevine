package widevine

import (
   "os"
   "testing"
)

func TestCbc(t *testing.T) {
   data, err := os.ReadFile("keyBox.bin")
   if err != nil {
      t.Fatal(err)
   }
   err = cbc(data)
   if err != nil {
      t.Fatal(err)
   }
}
