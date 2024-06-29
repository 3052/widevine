package widevine

import (
   "154.pages.dev/protobuf"
   "net/http"
)

func unpad(data []byte) []byte {
   if len(data) >= 1 {
      pad := data[len(data)-1]
      if len(data) >= int(pad) {
         data = data[:len(data)-int(pad)]
      }
   }
   return data
}

type PSSH struct {
   ContentId []byte
   KeyId []byte
}

func (p PSSH) Encode() []byte {
   var m protobuf.Message
   if p.KeyId != nil {
      m.AddBytes(2, p.KeyId)
   }
   if p.ContentId != nil {
      m.AddBytes(4, p.ContentId)
   }
   return m.Encode()
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
