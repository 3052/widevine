package widevine

import (
   "encoding/base64"
   "fmt"
   "testing"
)

// amcplus.com/movies/perfect-blue--1058032
const perfect_blue =  "AAAAVnBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADYIARIQd41tdrKESTqmJnLHZiJ/nxoNd2lkZXZpbmVfdGVzdCIIMTIzNDU2NzgyB2RlZmF1bHQ="

func TestProtectionSystem(t *testing.T) {
   var protect protectionSystem
   data, err := base64.StdEncoding.DecodeString(perfect_blue)
   if err != nil {
      t.Fatal(err)
   }
   if err := protect.New(data); err != nil {
      t.Fatal(err)
   }
   fmt.Printf("%q\n", protect.key_ids())
   content_id, ok := protect.content_id()
   fmt.Printf("%q %v\n", content_id, ok)
}
