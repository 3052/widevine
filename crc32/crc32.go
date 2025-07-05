package crc32

const (
   polynomial          = 0x04C11DB7 // Confirmed Poly: 0x04C11DB7
   initialValue uint32 = 0xFFFFFFFF // Confirmed Init: 0xFFFFFFFF
   finalXorValue = 0x00000000 // Confirmed XorOut: 0x00000000
)

func calculateCRC32MPEG2(data []byte) uint32 {
   crc := initialValue // Initialize the CRC register
   for _, b := range data {
      // XOR the current byte with the most significant byte of the CRC register.
      // This is standard for non-reflected input (RefIn: false).
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
