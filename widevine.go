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

type Pssh struct {
   ContentId []byte
   KeyId []byte
}

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
