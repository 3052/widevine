package widevine

import (
   "bytes"
   "encoding/base64"
   "encoding/json"
   "fmt"
   "net/http"
   "os"
   "testing"
)

func (t test_post) _Response_Body(s []byte) ([]byte, error) {
   _, s, _ = bytes.Cut(s, []byte{'\n'})
   var v struct {
      Client_ID struct {
         Token struct {
            Public_Key []byte `json:"publicKey"`
         }
      } `json:"clientId"`
   }
   err := json.Unmarshal(s, &v)
   if err != nil {
      return nil, err
   }
   return v.Client_ID.Token.Public_Key, nil
}

func (test_post) _Request_URL() string {
   return "https://integration.widevine.com/_/license_response"
}

func (t test_post) _Request_Body(src []byte) ([]byte, error) {
   buf := make([]byte, t.e.EncodedLen(len(src)))
   t.e.Encode(buf, src)
   return buf, nil
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
   test := test_post{base64.StdEncoding}
   pssh, err := test.e.DecodeString(post_pssh)
   if err != nil {
      t.Fatal(err)
   }
   mod, err := _New_Module(private_key, client_ID, pssh)
   if err != nil {
      t.Fatal(err)
   }
   key, err := mod._Post(test)
   if err != nil {
      t.Fatal(err)
   }
   fmt.Printf("%x\n", key)
}

func (test_post) _Request_Header() http.Header { return nil }

const post_pssh = "AAAARHBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAACQIARIBNRoNd2lkZXZpbmVfdGVzdCIKMjAxNV90ZWFycyoCU0Q="

type test_post struct {
   e *base64.Encoding
}
