package widevine

import (
   "154.pages.dev/protobuf"
   "bytes"
   "encoding/binary"
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
   SpecificHeader struct {
      Size uint32
      Type Type
      Version uint8
      Flags [3]byte
      SystemID SystemID
      DataSize uint32
   }
   Data protobuf.Message
}

func (p *protectionSystem) New(data []byte) error {
   buf := bytes.NewBuffer(data)
   err := binary.Read(buf, binary.BigEndian, &p.SpecificHeader)
   if err != nil {
      return err
   }
   return p.Data.Consume(buf.Bytes())
}

// optional bytes content_id = 4;
func (p protectionSystem) content_id() ([]byte, bool) {
   return p.Data.GetBytes(4)
}

// all of the Widevine PSSH I have seen so far are single `key_id`, so we are
// going to implement that for now, because its not clear what the logic would
// be with multiple key_ids.
func (p protectionSystem) key_id() ([]byte, bool) {
   // repeated bytes key_ids = 2;
   return p.Data.GetBytes(2)
}

func (protectionSystem) CDM(private_key, client_id []byte) (*CDM, error) {
   return nil, nil
}
