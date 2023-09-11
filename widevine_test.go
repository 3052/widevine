package widevine

import (
   "encoding/base64"
   "fmt"
   "net/http"
   "os"
   "testing"
)

type test_post base64.Encoding

func (test_post) Request_URL() string {
   return "https://integration.widevine.com/_/license_request"
}

func (test_post) Request_Header() http.Header { return nil }

func (t test_post) Request_Body(src []byte) ([]byte, error) {
   buf := make([]byte, t.EncodedLen(len(src)))
   t.Encode(buf, src)
   return buf, nil
}

func (t test_post) Response_Body(s []byte) ([]byte, error) {
   dbuf := make([]byte, t.DecodedLen(len(s)))
   n, err := t.Decode(dbuf, s)
   return dbuf[:n], err
}

func Test_Post(t *testing.T) {
   home, err := os.UserHomeDir()
   if err != nil {
      t.Fatal(err)
   }
   private_key, err := os.ReadFile(home + "/widevine/private_key.pem")
   if err != nil {
      t.Fatal(err)
   }
   client_ID, err := os.ReadFile(home + "/widevine/client_id.bin")
   if err != nil {
      t.Fatal(err)
   }
   pssh, err := base64.StdEncoding.DecodeString(test.pssh)
   if err != nil {
      t.Fatal(err)
   }
   mod, err := _New_Module(private_key, client_ID, pssh)
   if err != nil {
      t.Fatal(err)
   }
   key, err := mod.Post(test_post(base64.StdEncoding))
   if err != nil {
      t.Fatal(err)
   }
   fmt.Printf("%x\n", key)
}

var test_container = _Container{
   _ID: []byte{
      0xbd, 0xfa, 0x4d, 0x6c, 0xdb, 0x39, 0x70, 0x2e,
      0x5b, 0x68, 0x1f, 0x90, 0x61, 0x7f, 0x9a, 0x7e,
   },
   _Key: []byte{
      0xe2, 0x58, 0xb6, 0x7d, 0x75, 0x42, 0x0, 0x66,
      0xc8, 0x42, 0x4b, 0xd1, 0x42, 0xf8, 0x45, 0x65,
   },
}

func Test_Container(t *testing.T) {
   fmt.Println(test_container)
}
