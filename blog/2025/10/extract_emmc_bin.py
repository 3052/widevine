import sys
import os

## VARS ################################

B  = 2**00
KB = 2**10
MB = 2**20
GB = 2**30

BLOCK_SIZE = 0x200
HEADER_SIZE = 0x200000 # Header size is always 2MB

TYPE_PARTITION = 22592

OFFSET_NAME = 0x10
OFFSET_BASE = 0x08
OFFSET_SIZE = 0X0C

## FUNCTIONS ##############################

def createDirectory(dir):
	if not os.path.exists(dir): # if the directory does not exist
		os.makedirs(dir) # make the directory
	else: # the directory exists
		#removes all files in a folder
		for the_file in os.listdir(dir):
			file_path = os.path.join(dir, the_file)
			try:
				if os.path.isfile(file_path):
					os.unlink(file_path) # unlink (delete) the file
			except e:
				print (e)

def loadPart(file, offset, size):
	with open(file, 'rb') as f:
		f.seek(offset)
		return f.read(size)

def copyPart(src, dest, offset, size, bufsize = 16 * MB, append = False):
	
	if not os.path.exists(dest):
		append = False
	
	with open(src, 'rb') as f1:
		f1.seek(offset)
		with open(dest, 'ab' if append else 'wb') as f2:
			while size:
				chunk = min(bufsize, size)
				data = f1.read(chunk)
				f2.write(data)
				size -= chunk

## PROGRAMM ##############################

disk = False

# Parse args
if len(sys.argv) == 1:
	print ("Usage: unpack.py <emmc.bin> <block size [default: 512]> <output folder [default: ./emmc/]>\n")
	disk = input("Do you want open disk? (choose letter): ")
	print()
	if len(disk) == 1:
		# on Linux it's like /dev/sda1
		inputFile = "\\\\.\\"+disk.upper()+":"
	else:
		print("Nothing to do - exiting")
		quit()

if not disk:
	inputFile = sys.argv[1]

if not disk and not os.path.exists(inputFile):
	print ("No such file: {}".format(inputFile))
	quit()

if len(sys.argv) >= 3:
	BLOCK_SIZE = int(sys.argv[2])

if len(sys.argv) == 4:
	outputDirectory = sys.argv[3]
else:
	outputDirectory = 'emmc'

# Create output directory
createDirectory(outputDirectory)

# Find header
# Header size is 2MB
if disk:
	print ("Direct disk read mode - "+inputFile)
else:
	print ("\nFile size:  " + format(os.path.getsize(inputFile),",")+" Bytes")
	
print ("Block size: " + str(BLOCK_SIZE)+" Bytes")
print ("\nPartitions:\n")

header = loadPart(inputFile, 0, HEADER_SIZE)
copyPart(inputFile, os.path.join(outputDirectory, "~header"), 0, HEADER_SIZE)

partitions = []
n = 0

for x in range(0, len(header), BLOCK_SIZE):
	type = int.from_bytes(header[x:x+2], byteorder ='little')
	if type == TYPE_PARTITION:
		n += 1
		name = header[x+OFFSET_NAME:x+OFFSET_NAME+20].decode('ascii').rstrip('\x00')
		base = int.from_bytes(header[x+OFFSET_BASE:x+OFFSET_BASE+4], byteorder ='little')
		size = int.from_bytes(header[x+OFFSET_SIZE:x+OFFSET_SIZE+4], byteorder ='little')
		full_size = size * BLOCK_SIZE // 1024
		
		if full_size > 1024:
			full_size = str(full_size // 1024) + " MB"
		else:
			full_size = str(full_size) + " KB"
			
		print(str(n).rjust(2,'0') + ": " + name.ljust(30) + " " + str(str(base)+":"+str(size)).ljust(25) + " " + full_size )
		partitions.append({'name':name, 'base':base, 'size':size});

if len(partitions) < 1:
	print ("\nPartions are not found\n")
	quit()
	
print ("\nExtracting...\n")

all = str(len(partitions))
n = 1

for p in partitions:
	outFile = os.path.join(outputDirectory, p['name']+".bin")
	print("Saving ("+str(n).rjust(2,'0')+"/"+all+") "+(p['name']+" ["+str(p['base']) + ":" + str(p['size']) + "]").ljust(40)+" => "+outFile)
	copyPart(inputFile, outFile, p['base']*BLOCK_SIZE, p['size']*BLOCK_SIZE)
	n += 1
