package widevine

import (
   "encoding/base64"
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
   if err := module.SetPrivateKey(private_key); err != nil {
      t.Fatal(err)
   }
   if err := module.PSSH(client_ID, pssh); err != nil {
      t.Fatal(err)
   }
   key, err := module.Key(roku{})
   if err != nil {
      t.Fatal(err)
   }
   fmt.Printf("%x\n", key)
}

func (roku) Request_Header() (http.Header, bool) {
   return nil, false
}

type roku struct{}

func (roku) Request_Body(b []byte) ([]byte, error) {
   return b, nil
}

func (roku) Response_Body(b []byte) ([]byte, error) {
   return b, nil
}

func (roku) Request_URL() (string, bool) {
   return "https://wv-license.sr.roku.com/license/v1/license/wv?token=Lc1JXP0qydLJJacGpPijQx6PVdZUkOkkjKUQ1yX1G8xUNzSjsaQl_ReBS_0HPEks7baTOcLbZJBltyl4qDSYnvHOIVWXGY4ZZCMSIX2lPkKM9HrY2G-mfm3sbX6xIORKllMLb2DHFpJJIhTs4_iTSP5pyktnTOqU0quvQERvpJiioTumJBF73MOrIUN2yW3hZLNA5SZC88QRxguAbadUwD9krAbA2Nh1j5YACLInD2izaLAyASusqIYuNxVi_Pa-wsRW8A-u8hKGSGzmVH3LNjfo-QEiIr5IpQHhndmHN6fup3kMkdeCoHYQ5Qz7heMI24jRTR_DWo8tccy24xBXSLNdEgnN&traceId=d8859f64add3f8743bcc4aa1aca1695d&ExpressPlayToken=none", true
}
