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
   module, err := tests[name].cdm()
   if err != nil {
      return nil, err
   }
   body, err := module.request_signed()
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
   license, err := module.response(body)
   if err != nil {
      return nil, err
   }
   key, err := module.Key(license)
   if err != nil {
      return nil, err
   }
   res.Write(os.Stdout)
   return key, nil
}

type unwrapper func([]byte) ([]byte, error)

func (t tester) cdm() (*CDM, error) {
   home, err := os.UserHomeDir()
   if err != nil {
      return nil, err
   }
   client_id, err := os.ReadFile(home + "/widevine/client_id.bin")
   if err != nil {
      return nil, err
   }
   private_key, err := os.ReadFile(home + "/widevine/private_key.pem")
   if err != nil {
      return nil, err
   }
   data, err := t.data()
   if err != nil {
      return nil, err
   }
   var module CDM
   err = module.New(data, client_id, private_key)
   if err != nil {
      return nil, err
   }
   return &module, nil
}

func (t tester) data() (Data, error) {
   if t.pssh != "" {
      b, err := base64.StdEncoding.DecodeString(t.pssh)
      if err != nil {
         return nil, err
      }
      return PSSH(b), nil
   }
   b, err := hex.DecodeString(t.key_id)
   if err != nil {
      return nil, err
   }
   return KeyId(b), nil
}

type tester struct {
   key_id string
   pssh string
   url      string
}

var tests = map[string]tester{
   "amc": {
      url:      "amcplus.com/movies/blue-is-the-warmest-color--1027047",
      pssh: "CAESEK3zMvstBUFBn1RFkJBR01YaDXdpZGV2aW5lX3Rlc3QiCDEyMzQ1Njc4MgdkZWZhdWx0",
   },
   "ctv": {
      url:      "ctv.ca/movies/the-girl-with-the-dragon-tattoo-2011",
      pssh: "CAESEMsJVx7ryz9yhyAmV/a596YaCWJlbGxtZWRpYSISZmYtZDAxM2NhN2EtMjY0MjY1",
   },
   "roku": {
      url:      "therokuchannel.roku.com/watch/105c41ea75775968b670fbb26978ed76",
      pssh: "CAESEL36TWzbOXAuW2gfkGF/mn4aCmludGVydHJ1c3QiASo=",
   },
   "mubi": {
      url:      "mubi.com/films/yukis-sun",
      pssh: "CAESEO/Df05STk0/lAms0btFCf4aCHVzcC1jZW5jIhg3OE4vVGxKT1RUK1VDYXpSdTBVSi9nPT0qADIA",
   },
   "hulu": {
      url:      "hulu.com/watch/023c49bf-6a99-4c67-851c-4c9e7609cc1d",
      pssh: "CAESECG4LcLrsk1aqfhjHwRyZlAaBGh1bHUqAkhE",
   },
   "nbc": {
      url: "nbc.com/saturday-night-live/video/february-3-ayo-edebiri/9000283433",
      pssh: "CAESEGRuxmA57ENyp0hP3pVB2ZoaC2J1eWRybWtleW9zIhBkbsZgOexDcqdIT96VQdmaKgJIRA==",
   },
   "paramount": {
      url: "paramountplus.com/shows/video/bqsJh_z7o4AR6ktui_9y8wIHqzEEqbhr",
      pssh: "CAESED3g8zwbik/Olh7aqVDi5zIiIGJxc0poX3o3bzRBUjZrdHVpXzl5OHdJSHF6RUVxYmhyOAE=",
   },
   "stan": {
      url: "play.stan.com.au/programs/1768588",
      key_id: "0b5c271e61c244a8ab81e8363a66aa35",
   },
}
