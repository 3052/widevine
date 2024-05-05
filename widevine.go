package widevine

import (
   "154.pages.dev/protobuf"
   "net/http"
)

func PSSH(key_id, content_id []byte) []byte {
   var m protobuf.Message
   if key_id != nil {
      m.AddBytes(2, key_id)
   }
   if content_id != nil {
      m.AddBytes(4, content_id)
   }
   return m.Encode()
}

func unpad(data []byte) []byte {
   if len(data) >= 1 {
      pad := data[len(data)-1]
      if len(data) >= int(pad) {
         data = data[:len(data)-int(pad)]
      }
   }
   return data
}

type Poster interface {
   RequestUrl() (string, bool)
   RequestHeader() (http.Header, error)
   WrapRequest([]byte) ([]byte, error)
   UnwrapResponse([]byte) ([]byte, error)
}

type no_operation struct{}

func (no_operation) Read(buf []byte) (int, error) {
   return len(buf), nil
}
