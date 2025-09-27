package main

import (
   "bytes"
   "encoding/binary"
   "encoding/hex"
   "fmt"
   "os"
)

// Keybox holds the parsed data from a Widevine keybox file.
type Keybox struct {
   StableID     []byte
   DeviceAESKey []byte
   DeviceID     []byte
   Flags        uint32
   SystemID     uint32
}

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

// NewKeybox parses a raw byte slice and returns a validated Keybox object.
func NewKeybox(data []byte) (*Keybox, error) {
   length := len(data)
   if length != 128 && length != 132 {
      return nil, fmt.Errorf("invalid keybox length: %d. Should be 128 or 132 bytes", length)
   }

   if length == 132 {
      if !bytes.Equal(data[0x80:0x84], []byte("LVL1")) {
         return nil, fmt.Errorf("QSEE style keybox does not end in bytes 'LVL1'")
      }
      data = data[0:0x80]
   }

   if !bytes.Equal(data[0x78:0x7C], []byte("kbox")) {
      return nil, fmt.Errorf("invalid keybox magic")
   }

   // Verify the CRC checksum using the correct function
   payload := data[:0x7C]
   expectedCrc := binary.BigEndian.Uint32(data[0x7C : 0x7C+4])
   calculatedCrc := calculateCRC32MPEG2(payload) // <-- Using your working function

   if expectedCrc != calculatedCrc {
      return nil, fmt.Errorf("keybox CRC is bad. Expected: 0x%08X. Computed: 0x%08X", expectedCrc, calculatedCrc)
   }

   // If all checks pass, create and populate the struct
   kbox := &Keybox{
      StableID:     data[0x00:0x20],
      DeviceAESKey: data[0x20:0x30],
      DeviceID:     data[0x30:0x78],
   }

   kbox.Flags = binary.BigEndian.Uint32(kbox.DeviceID[0:4])
   kbox.SystemID = binary.BigEndian.Uint32(kbox.DeviceID[4:8])

   return kbox, nil
}

func main() {
   if len(os.Args) < 2 {
      fmt.Printf("Usage: %s <path_to_keybox_file>\n", os.Args[0])
      os.Exit(1)
   }
   keyboxFilePath := os.Args[1]

   data, err := os.ReadFile(keyboxFilePath)
   if err != nil {
      fmt.Printf("[!] Error: Could not read file '%s'. Reason: %v\n", keyboxFilePath, err)
      os.Exit(1)
   }

   fmt.Printf("--- Parsing Keybox File: %s ---\n", keyboxFilePath)

   keybox, err := NewKeybox(data)
   if err != nil {
      fmt.Printf("\n[!] Error: The provided file is not a valid keybox.\n")
      fmt.Printf("    Reason: %v\n", err)
      os.Exit(1)
   }

   stableIDStr := string(bytes.Trim(keybox.StableID, "\x00"))

   fmt.Println("\n[+] Keybox parsed successfully!")
   fmt.Println("---------------------------------")
   fmt.Printf("  Stable ID:      %s\n", stableIDStr)
   fmt.Printf("  System ID:      %d\n", keybox.SystemID)
   fmt.Printf("  Flags:            0x%08X\n", keybox.Flags)
   fmt.Printf("  Device AES Key:   %s\n", hex.EncodeToString(keybox.DeviceAESKey))
   fmt.Println("---------------------------------")
}
