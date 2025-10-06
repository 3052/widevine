package main

import (
   "bufio"
   "bytes"
   "encoding/binary"
   "errors"
   "fmt"
   "io"
   "log"
   "os"
   "path/filepath"
   "strconv"
   "strings"
)

// VARS
const (
   B             = 1 << 0
   KB            = 1 << 10
   MB            = 1 << 20
   GB            = 1 << 30
   HEADERSIZE    = 2 * MB // Header size is always 2MB
   TYPEPARTITION = 22592
   OFFSETNAME    = 0x10
   OFFSETBASE    = 0x08
   OFFSETSIZE    = 0x0C
)

var (
   BLOCKSIZE int64 = 0x200
   // ErrNotAPartition is returned when a data block is not a valid partition type.
   ErrNotAPartition = errors.New("data block is not a valid partition type")
)

// Partition struct to hold partition information
type Partition struct {
   Name string
   Base int64
   Size int64 // Size in blocks
}

// NewPartitionFromBytes acts as a constructor, parsing a partition from a byte slice.
func NewPartitionFromBytes(data []byte) (*Partition, error) {
   // Check if the block is of the correct partition type
   if binary.LittleEndian.Uint16(data[0:2]) != TYPEPARTITION {
      return nil, ErrNotAPartition
   }

   // Extract name, trimming null characters
   nameBytes := data[OFFSETNAME : OFFSETNAME+20]
   name := string(bytes.TrimRight(nameBytes, "\x00"))

   // Extract base and size, which are 4-byte little-endian unsigned integers
   base := binary.LittleEndian.Uint32(data[OFFSETBASE : OFFSETBASE+4])
   size := binary.LittleEndian.Uint32(data[OFFSETSIZE : OFFSETSIZE+4])

   return &Partition{
      Name: name,
      Base: int64(base),
      Size: int64(size),
   }, nil
}

// Extract saves the partition's data from the source file to a new file in the output directory.
func (p *Partition) Extract(srcFile *os.File, outputDir string) error {
   outFile := filepath.Join(outputDir, p.Name+".bin")

   // The print statement for the extraction action
   fmt.Printf("Saving %-40s => %s\n", p.logName(), outFile)

   // Calculate offset and size in bytes for the copy operation
   offsetBytes := p.Base * BLOCKSIZE
   sizeBytes := p.Size * BLOCKSIZE

   // Perform the actual file copy
   return copyPart(srcFile, outFile, offsetBytes, sizeBytes)
}

// logName provides a formatted string for logging purposes.
func (p *Partition) logName() string {
   return fmt.Sprintf("%s [%d:%d]", p.Name, p.Base, p.Size)
}

// String provides a human-readable summary of the partition, satisfying the fmt.Stringer interface.
func (p *Partition) String() string {
   sizeInKB := p.Size * BLOCKSIZE / KB
   var sizeStr string
   if sizeInKB >= KB { // If size is 1MB or more
      sizeStr = fmt.Sprintf("%d MB", sizeInKB/KB)
   } else {
      sizeStr = fmt.Sprintf("%d KB", sizeInKB)
   }
   return fmt.Sprintf("%-30s %-25s %s", p.Name, fmt.Sprintf("%d:%d", p.Base, p.Size), sizeStr)
}

// copyPart is a low-level utility function for copying a segment of file data.
func copyPart(srcFile *os.File, dest string, offset int64, size int64) error {
   // Seek to the starting position of the partition data in the source file
   if _, err := srcFile.Seek(offset, io.SeekStart); err != nil {
      return fmt.Errorf("failed to seek in source file: %w", err)
   }

   // Create the destination file
   destFile, err := os.Create(dest)
   if err != nil {
      return fmt.Errorf("failed to create destination file: %w", err)
   }
   defer destFile.Close()

   // Use io.Copy with an io.LimitReader for an efficient and safe copy
   _, err = io.Copy(destFile, io.LimitReader(srcFile, size))
   if err != nil {
      return fmt.Errorf("failed to copy data: %w", err)
   }
   return nil
}

// =================================================================
// CORRECTED: createDirectory now includes the logic to empty the directory if it exists.
// This fully matches the original Python script's behavior.
// =================================================================
func createDirectory(dir string) {
   // Check if the directory exists
   if _, err := os.Stat(dir); os.IsNotExist(err) {
      // If it doesn't exist, create it
      if err := os.MkdirAll(dir, 0755); err != nil {
         log.Fatalf("Failed to create directory: %v", err)
      }
   } else {
      // If it exists, remove all files inside it
      d, err := os.Open(dir)
      if err != nil {
         log.Fatalf("Failed to open directory for cleaning: %v", err)
      }
      defer d.Close()

      names, err := d.Readdirnames(-1)
      if err != nil {
         log.Fatalf("Failed to read directory contents: %v", err)
      }

      for _, name := range names {
         filePath := filepath.Join(dir, name)
         // Ensure we are only removing files, not subdirectories
         fileInfo, err := os.Stat(filePath)
         if err == nil && !fileInfo.IsDir() {
            if err := os.Remove(filePath); err != nil {
               log.Printf("Warning: could not remove file %s: %v", filePath, err)
            }
         }
      }
   }
}

// main function orchestrates the high-level logic.
func main() {
   var inputFile string
   var outputDirectory = "emmc"
   var diskMode = false

   // --- Argument Parsing ---
   if len(os.Args) < 2 {
      fmt.Println("Usage: unpack <emmc.bin> <block size [default: 512]> <output folder [default: ./emmc/]>")
      fmt.Print("Do you want open disk? (choose letter): ")
      reader := bufio.NewReader(os.Stdin)
      disk, _ := reader.ReadString('\n')
      disk = strings.TrimSpace(disk)
      fmt.Println()

      if len(disk) == 1 {
         // On Windows, the path is like \\.\PhysicalDrive0. For simplicity and matching the python,
         // we'll stick to the user's logic, but this is how it would typically be for a disk device.
         inputFile = `\\.\` + strings.ToUpper(disk) + ":"
         diskMode = true
      } else {
         fmt.Println("Nothing to do - exiting")
         return
      }
   }

   if !diskMode {
      inputFile = os.Args[1]
   }

   if len(os.Args) >= 3 {
      bs, err := strconv.ParseInt(os.Args[2], 10, 64)
      if err != nil {
         log.Fatalf("Invalid block size: %v", err)
      }
      BLOCKSIZE = bs
   }

   if len(os.Args) == 4 {
      outputDirectory = os.Args[3]
   }

   // --- Setup ---
   createDirectory(outputDirectory)

   srcFile, err := os.Open(inputFile)
   if err != nil {
      log.Fatalf("Failed to open input file %s: %v", inputFile, err)
   }
   defer srcFile.Close()

   // --- File Info & Header Extraction ---
   if diskMode {
      fmt.Printf("Direct disk read mode - %s\n", inputFile)
   } else {
      fileInfo, err := srcFile.Stat()
      if err != nil {
         log.Fatalf("Failed to get file info: %v", err)
      }
      fmt.Printf("\nFile size:  %d Bytes\n", fileInfo.Size())
   }

   fmt.Printf("Block size: %d Bytes\n", BLOCKSIZE)

   // Read header into a buffer
   header := make([]byte, HEADERSIZE)
   if _, err := srcFile.ReadAt(header, 0); err != nil {
      log.Fatalf("Failed to read header: %v", err)
   }

   // Save the header to its own file
   if err := copyPart(srcFile, filepath.Join(outputDirectory, "~header"), 0, HEADERSIZE); err != nil {
      log.Fatalf("Failed to extract header: %v", err)
   }

   // --- Partition Parsing ---
   fmt.Println("\nPartitions:\n")
   var partitions []*Partition
   // Iterate through the header buffer block by block
   for i := 0; i < HEADERSIZE; i += int(BLOCKSIZE) {
      block := header[i : i+int(BLOCKSIZE)]
      p, err := NewPartitionFromBytes(block)
      if errors.Is(err, ErrNotAPartition) {
         continue // This is expected, just not a partition block
      } else if err != nil {
         log.Printf("Error parsing block at offset %d: %v", i, err) // Log unexpected errors
         continue
      }
      partitions = append(partitions, p)
      fmt.Printf("%02d: %s\n", len(partitions), p)
   }

   if len(partitions) < 1 {
      fmt.Println("\nPartitions are not found")
      return
   }

   // --- Partition Extraction ---
   fmt.Println("\nExtracting...\n")
   for i, p := range partitions {
      // Add progress counter to the print statement
      fmt.Printf("(%02d/%d) ", i+1, len(partitions))
      if err := p.Extract(srcFile, outputDirectory); err != nil {
         // Log errors but continue trying to extract other partitions
         log.Printf("ERROR: Failed to extract partition %s: %v", p.Name, err)
      }
   }
}
