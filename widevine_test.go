package widevine

import (
   "encoding/base64"
   "fmt"
   "net/http"
   "os"
   "testing"
)

func Test_Key(t *testing.T) {
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
   pssh, err := base64.StdEncoding.DecodeString(post_pssh)
   if err != nil {
      t.Fatal(err)
   }
   mod, err := New_Module(private_key, client_ID, pssh)
   if err != nil {
      t.Fatal(err)
   }
   key, err := mod.Key(roku{})
   if err != nil {
      t.Fatal(err)
   }
   fmt.Printf("%x\n", key)
}

// therokuchannel.roku.com/watch/597a64a4a25c5bf6af4a8c7053049a6f
const post_pssh = "AAAAQ3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAACMIARIQKDOa149zRSDaJObgVz05LhoKaW50ZXJ0cnVzdCIBKg=="

func (roku) Request_URL() string {
   return "https://wv-license.sr.roku.com/license/v1/license/wv?token=Lc1JBqB7yN6beKcKrPiuQx6GVItUyr0hi6UTjSOhGZ1XYznxtPUl_RbbEa4NbhkgveuSb8fQYpcwsCx4pWLInqLLdgLCQ40eZCMSGzu6O0KM9HrY2G-mfm3sHQLEUulP5Cd3a2TNFZdJV2Xv5_TnOIJpyU1jTuDs16uvOkRvsJ6luRagJR0y-J-EJmocwUH4WrRZ8lFrzMQ2u3-AGrN_vFtGgx390fhQp7tLH4ImInykc6MtASyTpO0XOD1BvIC6_aF5ghOux3OOTTj_XXadIDT74Fo6NbFZ8gXzwcSSNbT_830Kz4Sdqmpevk2lytcuF2E46N8_h6YvwoxYUDIASMwsuMtIk933LA==&traceId=ebbf34f819eec313fefc97112f6fcc6c&ExpressPlayToken=none"
}

func (roku) Request_Header() http.Header {
   return nil
}

func (roku) Request_Body(b []byte) ([]byte, error) {
   return b, nil
}

func (roku) Response_Body(b []byte) ([]byte, error) {
   return b, nil
}

type roku struct{}
