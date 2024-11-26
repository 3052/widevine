package widevine

import (
   "encoding/base64"
   "fmt"
   "reflect"
   "testing"
)

func TestSize(t *testing.T) {
   a := reflect.TypeOf(&struct{}{}).Size()
   for _, test := range size_tests {
      b := reflect.TypeOf(test).Size()
      if b > a {
         fmt.Printf("%v *%T\n", b, test)
      } else {
         fmt.Printf("%v %T\n", b, test)
      }
   }
}

var size_tests = []any{
   Cdm{},
   Pssh{},
   no_operation{},
}

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
