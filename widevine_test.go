package widevine

import (
   "encoding/base64"
   "encoding/hex"
   "fmt"
   "net/http"
   "os"
   "testing"
)

type hulu struct{}

func (hulu) Request_Body(b []byte) ([]byte, error) {
   return b, nil
}

func (hulu) Request_URL() string {
   return "https://hulu.playback.edge.bamgrid.com/widevine-hulu/v1/hulu/vod/obtain-license-legacy/196861183?deejay_device_id=166&nonce=252683275&signature=1700045165_dc9be3e8018e31daf9fcf2847079ef8bcb92db4d"
}

func (hulu) Request_Header() http.Header {
   return nil
}

func (hulu) Response_Body(b []byte) ([]byte, error) {
   return b, nil
}

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
   mod, err := New_Module(private_key, client_ID, kid, nil)
   if err != nil {
      t.Fatal(err)
   }
   key, err := mod.Key(hulu{})
   if err != nil {
      t.Fatal(err)
   }
   fmt.Printf("%x\n", key)
}

const hulu_KID = "21b82dc2ebb24d5aa9f8631f04726650"

type roku struct{}

func (roku) Request_Body(b []byte) ([]byte, error) {
   return b, nil
}

func (roku) Response_Body(b []byte) ([]byte, error) {
   return b, nil
}

func (roku) Request_Header() http.Header {
   return nil
}

func (roku) Request_URL() string {
   return "https://wv-license.sr.roku.com/license/v1/license/wv?token=Lc1LCaApyoWbcacOq6WuQx6HA9xUkesg0KUZjCfxGMsAZz2mt6Ql_RDbRvkOPxopvrTFOJeGMsZg4C8o_WXOn6KZclDEEdgeZCMSMWGJOUKM9HrY2G-mfm3sbX6xIORKllMLb2DHFpJJIhTs4_iTSP5pyktnTOqU0quvQERvpJiioTumJBF73MOrIUN2yW3hZLNA5SZC88QRxguAbadUwD9krAbA2Nh1j5YACLInD2izaLAyASusqIYuNxVi_Pa-wsRW8A-u8hKGSGzmVH3LNjfo-QEiIr5IpQHhndmHN6fup3kMkdeCoHYQ5Qz7heMIy4TtSh9p43N9PJTXWenzP0ndiXmm&traceId=cb510ee12f223eab65e3a0702424e1cc&ExpressPlayToken=none"
}

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
   mod, err := New_Module(private_key, client_ID, nil, pssh)
   if err != nil {
      t.Fatal(err)
   }
   key, err := mod.Key(roku{})
   if err != nil {
      t.Fatal(err)
   }
   fmt.Printf("%x\n", key)
}
