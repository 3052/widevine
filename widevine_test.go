package widevine

import (
   "bufio"
   "bytes"
   "encoding/base64"
   "encoding/hex"
   "errors"
   "fmt"
   "io"
   "net/http"
   "os"
   "testing"
)

func (t tester) get_pssh(key_id []byte) ([]byte, error) {
   if t.pssh != "" {
      return base64.StdEncoding.DecodeString(t.pssh)
   }
   return Pssh{KeyId: key_id}.Marshal(), nil
}

type tester struct {
   key_id string
   pssh string
   url      string
}

func TestCtv(t *testing.T) {
   key, err := request("ctv", nil)
   if err != nil {
      t.Fatal(err)
   }
   fmt.Printf("%x\n", key)
}

func request(name string, unwrap unwrapper) ([]byte, error) {
   file, err := os.Open("testdata/" + name + ".bin")
   if err != nil {
      return nil, err
   }
   defer file.Close()
   req, err := http.ReadRequest(bufio.NewReader(file))
   if err != nil {
      return nil, err
   }
   test := tests[name]
   key_id, err := hex.DecodeString(test.key_id)
   if err != nil {
      return nil, err
   }
   cdm, err := test.module(key_id)
   if err != nil {
      return nil, err
   }
   data, err := cdm.sign_request()
   if err != nil {
      return nil, err
   }
   req.Body = io.NopCloser(bytes.NewReader(data))
   req.Header.Del("accept-encoding")
   req.RequestURI = ""
   req.URL.Host = req.Host
   req.URL.Scheme = "https"
   req.ContentLength = int64(len(data))
   resp, err := http.DefaultClient.Do(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()
   if resp.StatusCode != http.StatusOK {
      var b bytes.Buffer
      resp.Write(&b)
      return nil, errors.New(b.String())
   }
   data, err = io.ReadAll(resp.Body)
   if err != nil {
      return nil, err
   }
   if unwrap != nil {
      data, err = unwrap(data)
      if err != nil {
         return nil, err
      }
   }
   key, err := cdm.decrypt(data, key_id)
   if err != nil {
      return nil, err
   }
   resp.Write(os.Stdout)
   return key, nil
}

var tests = map[string]tester{
   "ctv": {
      key_id: "cb09571eebcb3f7287202657f6b9f7a6",
      pssh: "CAESEMsJVx7ryz9yhyAmV/a596YaCWJlbGxtZWRpYSISZmYtZDAxM2NhN2EtMjY0MjY1",
      url:      "ctv.ca/movies/the-girl-with-the-dragon-tattoo-2011",
   },
}

func (t tester) module(key_id []byte) (*Module, error) {
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
   pssh, err := t.get_pssh(key_id)
   if err != nil {
      return nil, err
   }
   var cdm Module
   err = cdm.New(private_key, client_id, pssh)
   if err != nil {
      return nil, err
   }
   return &cdm, nil
}

type unwrapper func([]byte) ([]byte, error)
