import pefile
import sys

if __name__ == "__main__":
	pe = pefile.PE(sys.argv[1])
	data = open(sys.argv[1], 'rb').read()
	sizeofHdrs = pe.OPTIONAL_HEADER.SizeOfHeaders
	new_file = data[:sizeofHdrs]
	#Might need to put them in order by PointerToRawData just validate they are in order
	for sect in pe.sections:
		new_file += data[sect.VirtualAddress:sect.VirtualAddress+sect.SizeOfRawData]
	open(sys.argv[2], 'wb').write(new_file)
