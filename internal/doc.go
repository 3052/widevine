package widevine

import (
   "154.pages.dev/protobuf"
   "bytes"
   "encoding/binary"
   "net/http"
)

// ISO/IEC 14496-12
//  aligned(8) class Box (
//     unsigned int(32) boxtype, optional unsigned int(8)[16] extended_type
//  ) {
//     BoxHeader(boxtype, extended_type);
//     // the remaining bytes are the BoxPayload
//  }
//
//  aligned(8) class BoxHeader (
//     unsigned int(32) boxtype, optional unsigned int(8)[16] extended_type
//  ) {
//     unsigned int(32) size;
//     unsigned int(32) type = boxtype;
//     if (size==1) {
//        unsigned int(64) largesize;
//     } else if (size==0) {
//        // box extends to end of file
//     }
//     if (boxtype=='uuid') {
//        unsigned int(8)[16] usertype = extended_type;
//     }
//  }
//
//  aligned(8) class FullBox(
//     unsigned int(32) boxtype,
//     unsigned int(8) v,
//     bit(24) f,
//     optional unsigned int(8)[16] extended_type
//  ) extends Box(boxtype, extended_type) {
//     FullBoxHeader(v, f);
//     // the remaining bytes are the FullBoxPayload
//  }
//
//  aligned(8) class FullBoxHeader(unsigned int(8) v, bit(24) f) {
//     unsigned int(8) version = v;
//     bit(24) flags = f;
//  }
//
// ISO/IEC 23001-7
//  aligned(8) class ProtectionSystemSpecificHeaderBox extends FullBox(
//     'pssh', version, flags=0,
//  ) {
//     unsigned int(8)[16] SystemID;
//     if (version > 0) {
//        unsigned int(32) KID_count;
//        {
//           unsigned int(8)[16] KID;
//        } [KID_count];
//     }
//     unsigned int(32) DataSize;
//     unsigned int(8)[DataSize] Data;
//  }
type protectionSystem struct {
   specificHeader struct {
      Size uint32
      Type uint32
      Version uint8
      Flags [3]byte
      SystemID [16]uint8
      DataSize uint32
   }
   data protobuf.Message
}

// optional bytes content_id = 4;
func (p protectionSystem) content_id() ([]byte, bool) {
   return p.data.GetBytes(4)
}

type poster interface {
   requestHeader() (http.Header, bool)
   requestBody([]byte) ([]byte, error)
   responseBody([]byte) ([]byte, error)
   requestUrl() (string, bool)
}

func (p *protectionSystem) New(data []byte) error {
   buf := bytes.NewBuffer(data)
   err := binary.Read(buf, binary.BigEndian, &p.specificHeader)
   if err != nil {
      return err
   }
   return p.data.Consume(buf.Bytes())
}

// repeated bytes key_ids = 2;
func (p protectionSystem) key_ids() [][]byte {
   var bs [][]byte
   for _, field := range p.data {
      if b, ok := field.GetBytes(2); ok {
         bs = append(bs, b)
      }
   }
   return bs
}

func (protectionSystem) cdm(private_key, client_id []byte) (*cdm, error) {
   return nil, nil
}

func (cdm) keyContainer(poster) ([]keyContainer, error) {
   return nil, nil
}

func (protectionSystem) key([]keyContainer) ([]byte, bool) {
   return nil, false
}

type cdm struct{}

type keyContainer struct {
   id []byte
   key []byte
}
