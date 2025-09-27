package widevine

import (
   "encoding/binary"
   "errors"
   "fmt"
)

func calculate_crc32_mpeg2(data []byte) uint32 {
   const (
      polynomial    uint32 = 0x04C11DB7
      initialValue  uint32 = 0xFFFFFFFF
      finalXorValue uint32 = 0x00000000
   )
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

func (k *keybox) unmarshal(data []byte) error {
   if len(data) != 128 {
      return errors.New("invalid keybox length. should be 128 bytes")
   }
   k.device_id = string(data[:32])                  // 0:32
   k.device_key = [16]byte(data[32:])               // 32:48
   k.flags = binary.BigEndian.Uint32(data[48:])     // 48:52
   k.system_id = binary.BigEndian.Uint32(data[52:]) // 52:56
   k.provisioning_token = [64]byte(data[56:])       // 56:120
   // magic number
   k.magic_number = string(data[120:124])
   if k.magic_number != "kbox" {
      return errors.New("invalid keybox magic")
   }
   // crc32
   k.crc32 = binary.BigEndian.Uint32(data[124:])
   if k.crc32 != calculate_crc32_mpeg2(data[:124]) {
      return errors.New("keybox CRC is bad")
   }
   return nil
}

// wikipedia.org/wiki/Widevine#Input_→_output_overview
type keybox struct {
   device_id          string
   device_key         [16]byte
   flags              uint32
   system_id          uint32
   provisioning_token [64]byte
   magic_number       string
   crc32              uint32
}

func (k *keybox) String() string {
   var b []byte
   b = fmt.Appendln(b, "device id =", k.device_id)
   b = fmt.Appendf(b, "device key = %x\n", k.device_key)
   b = fmt.Appendln(b, "flags =", k.flags)
   b = fmt.Appendln(b, "system id =", k.system_id)
   b = fmt.Appendf(b, "provisioning token = %x\n", k.provisioning_token)
   b = fmt.Appendln(b, "magic number =", k.magic_number)
   b = fmt.Append(b, "crc32 = ", k.crc32)
   return string(b)
}
