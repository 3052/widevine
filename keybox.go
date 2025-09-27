package widevine

import (
   "bytes"
   "encoding/binary"
   "fmt"
)

// --- User-provided CRC32/MPEG-2 Implementation (Correct) ---
const (
   polynomial    uint32 = 0x04C11DB7 // Confirmed Poly: 0x04C11DB7
   initialValue  uint32 = 0xFFFFFFFF // Confirmed Init: 0xFFFFFFFF
   finalXorValue uint32 = 0x00000000 // Confirmed XorOut: 0x00000000
)

// calculateCRC32MPEG2 calculates the CRC using the non-reflected MPEG-2 standard.
func calculateCRC32MPEG2(data []byte) uint32 {
   crc := initialValue // Initialize the CRC register
   for _, b := range data {
      // XOR the current byte with the most significant byte of the CRC register.
      crc ^= uint32(b) << 24
      // Process 8 bits for the current byte
      for i := 0; i < 8; i++ {
         // If the most significant bit (MSB) of the CRC register is 1
         if (crc & 0x80000000) != 0 {
            // Shift the CRC left by 1 bit, and XOR with the polynomial
            crc = (crc << 1) ^ polynomial
         } else {
            // Just shift the CRC left by 1 bit
            crc = (crc << 1)
         }
      }
   }
   return crc ^ finalXorValue
}

func (k *Keybox) unmarshal(data []byte) error {
   length := len(data)
   if length != 128 && length != 132 {
      return fmt.Errorf("invalid keybox length: %d. Should be 128 or 132 bytes", length)
   }
   if length == 132 {
      if !bytes.Equal(data[0x80:0x84], []byte("LVL1")) {
         return fmt.Errorf("QSEE style keybox does not end in bytes 'LVL1'")
      }
      data = data[0:0x80]
   }
   if !bytes.Equal(data[0x78:0x7C], []byte("kbox")) {
      return fmt.Errorf("invalid keybox magic")
   }
   payload := data[:0x7C]
   expectedCrc := binary.BigEndian.Uint32(
      data[0x7C:][:4],
      //data[0x7C : 0x7C+4],
   )
   calculatedCrc := calculateCRC32MPEG2(payload) // <-- Using your working function
   if expectedCrc != calculatedCrc {
      return fmt.Errorf("keybox CRC is bad. Expected: 0x%08X. Computed: 0x%08X", expectedCrc, calculatedCrc)
   }
   k.StableID = data[0x00:0x20]
   k.DeviceAESKey = data[0x20:0x30]
   k.DeviceID = data[0x30:0x78]
   k.Flags = binary.BigEndian.Uint32(k.DeviceID[:4])
   k.SystemID = binary.BigEndian.Uint32(k.DeviceID[4:8])
   return nil
}

// Keybox holds the parsed data from a Widevine keybox file.
type Keybox struct {
   StableID     []byte
   DeviceAESKey []byte
   DeviceID     []byte
   Flags        uint32
   SystemID     uint32
}
