package widevine

import (
   "bufio"
   "bytes"
   "encoding/base64"
   "encoding/hex"
   "errors"
   "io"
   "net/http"
   "os"
)

var tests = map[string]tester{
   "ctv": {
      key_id: "cb09571eebcb3f7287202657f6b9f7a6",
      pssh: "CAESEMsJVx7ryz9yhyAmV/a596YaCWJlbGxtZWRpYSISZmYtZDAxM2NhN2EtMjY0MjY1",
      url:      "ctv.ca/movies/the-girl-with-the-dragon-tattoo-2011",
   },
   "stan": {
      key_id: "0b5c271e61c244a8ab81e8363a66aa35",
      url: "play.stan.com.au/programs/1768588",
   },
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
   module, err := test.cdm(key_id)
   if err != nil {
      return nil, err
   }
   body, err := module.sign_request()
   if err != nil {
      return nil, err
   }
   req.Body = io.NopCloser(bytes.NewReader(body))
   req.Header.Del("accept-encoding")
   req.RequestURI = ""
   req.URL.Host = req.Host
   req.URL.Scheme = "https"
   req.ContentLength = int64(len(body))
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
   if unwrap != nil {
      body, err = unwrap(body)
      if err != nil {
         return nil, err
      }
   }
   key, err := module.decrypt(body, key_id)
   if err != nil {
      return nil, err
   }
   res.Write(os.Stdout)
   return key, nil
}

func (t tester) cdm(key_id []byte) (*CDM, error) {
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
   var module CDM
   err = module.New(private_key, client_id, pssh)
   if err != nil {
      return nil, err
   }
   return &module, nil
}

func (t tester) get_pssh(key_id []byte) ([]byte, error) {
   if t.pssh != "" {
      return base64.StdEncoding.DecodeString(t.pssh)
   }
   return PSSH(key_id, nil), nil
}

type unwrapper func([]byte) ([]byte, error)

type tester struct {
   key_id string
   pssh string
   url      string
}
