package widevine

import (
   "41.neocities.org/protobuf"
   "net/http"
)

func (p Pssh) Marshal() []byte {
   message := protobuf.Message{}
   if p.KeyId != nil {
      message.AddBytes(2, p.KeyId)
   }
   if p.ContentId != nil {
      message.AddBytes(4, p.ContentId)
   }
   return message.Marshal()
}

func unpad(b []byte) []byte {
   if len(b) >= 1 {
      pad := b[len(b)-1]
      if len(b) >= int(pad) {
         b = b[:len(b)-int(pad)]
      }
   }
   return b
}

type Pssh struct {
   ContentId []byte
   KeyId []byte
}

type Poster interface {
   RequestUrl() (string, bool)
   RequestHeader() (http.Header, error)
   WrapRequest([]byte) ([]byte, error)
   UnwrapResponse([]byte) ([]byte, error)
}

type no_operation struct{}

func (no_operation) Read(b []byte) (int, error) {
   return len(b), nil
}
