package widevine

import (
   "encoding/base64"
   "os"
)

func (t tester) get_pssh(key_id []byte) ([]byte, error) {
   if t.pssh != "" {
      return base64.StdEncoding.DecodeString(t.pssh)
   }
   return Pssh{KeyId: key_id}.Encode(), nil
}

var tests = map[string]tester{
   "ctv": {
      key_id: "cb09571eebcb3f7287202657f6b9f7a6",
      pssh: "CAESEMsJVx7ryz9yhyAmV/a596YaCWJlbGxtZWRpYSISZmYtZDAxM2NhN2EtMjY0MjY1",
      url:      "ctv.ca/movies/the-girl-with-the-dragon-tattoo-2011",
   },
}

func (t tester) cdm(key_id []byte) (*Cdm, error) {
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
   var module Cdm
   err = module.New(private_key, client_id, pssh)
   if err != nil {
      return nil, err
   }
   return &module, nil
}

type unwrapper func([]byte) ([]byte, error)

type tester struct {
   key_id string
   pssh string
   url      string
}
