package widevine

import (
   "bufio"
   "bytes"
   "errors"
   "fmt"
   "io"
   "net/http"
   "os"
   "testing"
)

func TestRoku(t *testing.T) {
   key, err := request("roku")
   if err != nil {
      t.Fatal(err)
   }
   fmt.Printf("%x\n", key)
}

func TestNbc(t *testing.T) {
   key, err := request("nbc")
   if err != nil {
      t.Fatal(err)
   }
   fmt.Printf("%x\n", key)
}

func request(name string) ([]byte, error) {
   home, err := os.UserHomeDir()
   if err != nil {
      return nil, err
   }
   private_key, err := os.ReadFile(home + "/widevine/private_key.pem")
   if err != nil {
      return nil, err
   }
   client_id, err := os.ReadFile(home + "/widevine/client_id.bin")
   if err != nil {
      return nil, err
   }
   file, err := os.Open("testdata/" + name + ".bin")
   if err != nil {
      return nil, err
   }
   defer file.Close()
   req, err := http.ReadRequest(bufio.NewReader(file))
   if err != nil {
      return nil, err
   }
   var protect PSSH
   protect.Data = tests[name].pssh.Encode()
   protect.m = tests[name].pssh
   module, err := protect.CDM(private_key, client_id)
   if err != nil {
      return nil, err
   }
   body, err := module.request_signed()
   if err != nil {
      return nil, err
   }
   req.Body = io.NopCloser(bytes.NewReader(body))
   req.ContentLength = 0
   req.RequestURI = ""
   //req.Header.Set("content-type", "application/x-protobuffer")
   res, err := http.DefaultClient.Do(req)
   if err != nil {
      return nil, err
   }
   defer res.Body.Close()
   if res.StatusCode != http.StatusOK {
      var b bytes.Buffer
      res.Write(&b)
      return nil, errors.New(b.String())
   }
   body, err = io.ReadAll(res.Body)
   if err != nil {
      return nil, err
   }
   license, err := module.response(body)
   if err != nil {
      return nil, err
   }
   key, ok := module.Key(license)
   if !ok {
      return nil, errors.New("CDM.Key")
   }
   res.Write(os.Stdout)
   return key, nil
}
