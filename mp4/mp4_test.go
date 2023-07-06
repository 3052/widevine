package mp4

import (
   "bytes"
   "encoding/hex"
   "fmt"
   "os"
   "testing"
)

type test_type struct {
   dec_path string
   enc_path string
   key string
}

var tests = []test_type{
   {
      "ignore/dec-piff.mp4",
      "ignore/enc-piff.mp4",
      "680a46ebd6cf2b9a6a0b05a24dcf944a",
   }, {
      "ignore/dec-cbcs.mp4",
      "ignore/enc-cbcs.mp4",
      "22bdb0063805260307ee5045c0f3835a",
   },
}

func Test_Decrypt(t *testing.T) {
   for _, test := range tests {
      fmt.Println(test.enc_path)
      enc_data, err := os.ReadFile(test.enc_path)
      if err != nil {
         t.Fatal(err)
      }
      key, err := hex.DecodeString(test.key)
      if err != nil {
         t.Fatal(err)
      }
      dec := make(Decrypt)
      dec_data := new(bytes.Buffer)
      err = dec.Init(bytes.NewReader(enc_data), dec_data)
      if err != nil {
         t.Fatal(err)
      }
      err = dec.Segment(bytes.NewReader(enc_data), dec_data, key)
      if err != nil {
         t.Fatal(err)
      }
      err = os.WriteFile(test.dec_path, dec_data.Bytes(), 0666)
      if err != nil {
         t.Fatal(err)
      }
   }
}
