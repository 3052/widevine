package widevine

import (
   "encoding/base64"
   "encoding/hex"
   "fmt"
   "net/http"
   "os"
   "testing"
)

func Test_Roku(t *testing.T) {
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
   pssh, err := base64.StdEncoding.DecodeString(tests[1].pssh)
   if err != nil {
      t.Fatal(err)
   }
   var module DecryptionModule
   if err := module.New(private_key, client_ID, nil, pssh); err != nil {
      t.Fatal(err)
   }
   key, err := module.Key(roku{})
   if err != nil {
      t.Fatal(err)
   }
   fmt.Printf("%x\n", key)
}

func (hulu) Request_Header() (http.Header, bool) {
   return nil, false
}

func (roku) Request_Header() (http.Header, bool) {
   return nil, false
}

func (hulu) Request_URL() (string, bool) {
   return "https://hulu.playback.edge.bamgrid.com/widevine-hulu/v1/hulu/vod/obtain-license-legacy/196861183?deejay_device_id=166&nonce=252683275&signature=1701864514_f7e7ce0e7cefdaa486b3d768538e62f7a6df2fbd", true
}

func (roku) Request_URL() (string, bool) {
   return "https://wv-license.sr.roku.com/license/v1/license/wv?token=Lc0YXaB9ntebdKcKqvP4Qx7QUIxUyroni6VB0iOnHcgBNm2m5P8l_UCLQK0KakZ87rPDb8aBYMEw7Cl6_2PIl6GfdlfFGN0ZZCMSdhruPkKM9HrY2G-mfm3sbX6xIORKllMLb2DHFpJJIhTs4_iTSP5pyktnTOqU0quvQERvpJiioTumJBF73MOrIUN2yW3hZLNA5SZC88QRxguAbadUwD9krAbA2Nh1j5YACLInD2izaLAyASusqIYuNxVi_Pa-wsRW8A-u8hKGSGzmVH3LNjfo-QEiIr5IpQHhndmHN6fup3kMkdeCoHYQ5Qz7heMIjJCLTR_a5xsSfiXMYP45Br7UItMb&traceId=323e409dba4ebb3ef9cac6181263d8fd&ExpressPlayToken=none", true
}
type hulu struct{}

func (hulu) Request_Body(b []byte) ([]byte, error) {
   return b, nil
}

func (hulu) Response_Body(b []byte) ([]byte, error) {
   return b, nil
}

type roku struct{}

func (roku) Request_Body(b []byte) ([]byte, error) {
   return b, nil
}

func (roku) Response_Body(b []byte) ([]byte, error) {
   return b, nil
}

const hulu_KID = "21b82dc2ebb24d5aa9f8631f04726650"

func Test_Hulu(t *testing.T) {
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
   kid, err := hex.DecodeString(hulu_KID)
   if err != nil {
      t.Fatal(err)
   }
   var module DecryptionModule
   if err := module.New(private_key, client_ID, kid, nil); err != nil {
      t.Fatal(err)
   }
   key, err := module.Key(hulu{})
   if err != nil {
      t.Fatal(err)
   }
   fmt.Printf("%x\n", key)
}

