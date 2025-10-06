package main

import (
   "bytes"
   "encoding/binary"
   "flag"
   "fmt"
   "io"
   "log"
   "os"
   "path/filepath"
)

// Constants defined in the Python script
const (
   B  = 1 << (10 * 0) // 2^0
   KB = 1 << (10 * 1) // 2^10
   MB = 1 << (10 * 2) // 2^20
   GB = 1 << (10 * 3) // 2^30

   DefaultBlockSize = 512
   HeaderSize       = 2 * MB // Header size is always 2MB

   TypePartition = 22592 // Magic number to identify a partition entry

   OffsetName = 0x10
   OffsetBase = 0x08
   OffsetSize = 0x0C
)

const outputDir = "emmc"

// Partition struct holds information about a single partition.
type Partition struct {
   Name string
   Base uint32 // Base address in blocks
   Size uint32 // Size in blocks
}

// copyPart is now more efficient, accepting an open file handle (io.ReadSeeker).
func copyPart(srcFile io.ReadSeeker, destPath string, offset, size int64) error {
   // Seek to the correct offset in the already open source file.
   if _, err := srcFile.Seek(offset, io.SeekStart); err != nil {
      return fmt.Errorf("could not seek in source file to offset %d: %w", offset, err)
   }
   destFile, err := os.Create(destPath)
   if err != nil {
      return fmt.Errorf("could not create destination file %s: %w", destPath, err)
   }
   defer destFile.Close()
   written, err := io.CopyN(destFile, srcFile, size)
   if err != nil {
      return fmt.Errorf("error copying data to %s: %w", destPath, err)
   }
   if written != size {
      return fmt.Errorf("expected to write %d bytes, but only wrote %d", size, written)
   }
   return nil
}

// parsePartitions finds and parses partitions from the given header data.
func parsePartitions(header []byte) []Partition {
   var partitions []Partition
   for i := 0; i+DefaultBlockSize <= len(header); i += DefaultBlockSize {
      block := header[i : i+2]
      partitionType := binary.LittleEndian.Uint16(block)

      if partitionType == TypePartition {
         // Extract name, base, and size from the block
         nameBytes := header[i+OffsetName : i+OffsetName+20]
         // Find the null terminator and trim the string
         nullIndex := bytes.IndexByte(nameBytes, 0)
         if nullIndex == -1 {
            nullIndex = len(nameBytes)
         }
         name := string(nameBytes[:nullIndex])

         base := binary.LittleEndian.Uint32(header[i+OffsetBase : i+OffsetBase+4])
         size := binary.LittleEndian.Uint32(header[i+OffsetSize : i+OffsetSize+4])

         partitions = append(partitions, Partition{Name: name, Base: base, Size: size})
      }
   }
   return partitions
}

func main() {
   inputFile := flag.String("i", "", "input file")
   flag.Parse()
   if *inputFile == "" {
      flag.Usage()
      return
   }

   err := os.Mkdir(outputDir, os.ModePerm)
   if err != nil && !os.IsExist(err) { // Check if the error is something other than "already exists"
      log.Fatalf("Failed to create output directory: %v", err)
   }

   // Open the source file ONCE here.
   srcFile, err := os.Open(*inputFile)
   if err != nil {
      log.Fatalf("Failed to open input file: %v", err)
   }
   // Defer the close until the main function exits.
   defer srcFile.Close()

   // 1. Read the header from the input file
   header := make([]byte, HeaderSize)
   // Use the already-open srcFile to read the header
   n, err := io.ReadFull(srcFile, header)
   if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
      log.Fatalf("Failed to read header from file: %v", err)
   }
   if n < HeaderSize {
      fmt.Printf("Warning: File size is less than header size. Read %d bytes.\n", n)
      header = header[:n] // Truncate header to actual bytes read
   }

   // Save the header to a file
   headerPath := filepath.Join(outputDir, "~header")
   if err := os.WriteFile(headerPath, header, 0644); err != nil {
      log.Fatalf("Failed to save header file: %v", err)
   }

   // 2. Find and parse partitions within the header by calling the new function
   partitions := parsePartitions(header)
   if len(partitions) < 1 {
      log.Fatal("\nPartitions are not found\n")
   }

   fmt.Println("\nPartitions:\n")
   for i, p := range partitions {
      // Calculate human-readable size
      fullSizeKB := (int64(p.Size) * DefaultBlockSize) / KB
      var fullSizeStr string
      if fullSizeKB > 1024 {
         fullSizeStr = fmt.Sprintf("%d MB", fullSizeKB/1024)
      } else {
         fullSizeStr = fmt.Sprintf("%d KB", fullSizeKB)
      }

      // Print partition info
      partNum := i + 1
      baseAndSize := fmt.Sprintf("%d:%d", p.Base, p.Size)
      fmt.Printf("%02d: %-30s %-25s %s\n", partNum, p.Name, baseAndSize, fullSizeStr)
   }

   fmt.Println("\nExtracting...\n")

   // 3. Extract each partition
   for i, p := range partitions {
      outFile := filepath.Join(outputDir, p.Name+".bin")

      infoStr := fmt.Sprintf("%s [%d:%d]", p.Name, p.Base, p.Size)
      fmt.Printf("Saving (%02d/%d) %-40s => %s\n", i+1, len(partitions), infoStr, outFile)

      // Calculate offset and size in bytes using int64 to avoid overflow
      offsetBytes := int64(p.Base) * DefaultBlockSize
      sizeBytes := int64(p.Size) * DefaultBlockSize

      // Pass the open srcFile handle to the updated copyPart function.
      err = copyPart(srcFile, outFile, offsetBytes, sizeBytes)
      if err != nil {
         log.Printf("ERROR: Failed to extract partition %s: %v", p.Name, err)
      }
   }
}
