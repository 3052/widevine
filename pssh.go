package widevine

import "41.neocities.org/protobuf"

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
