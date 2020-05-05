import pefile
import sys


def find_cave(file_name, min_size):
    try:
        pe = pefile.PE(file_name)

    except pefile.PEFormatError as e:
        print(f"[*] {e.args[0]}")
        sys.exit()

    image_base = pe.OPTIONAL_HEADER.ImageBase
    print(f"[*] Searching for code cave with minimal size of {min_size} bytes.")
    print(f"[*] Image base is 0x{image_base}")

    if pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040:
        print("[*] ASLR is enabled, Virtual address might be different while program will be executed.")

    file = open(file_name, 'rb')

    for section in pe.sections:
        permissions = ''
        characteristics = getattr(section, 'Characteristics')
        if characteristics & 0x20000000:
            permissions += 'Executable '
        if characteristics & 0x40000000:
            permissions += 'Readable '
        if characteristics & 0x80000000:
            permissions += 'Writeable'

        if section.SizeOfRawData != 0:
            pos = 0
            count = 0
            file.seek(section.PointerToRawData, 0)
            data = file.read(section.SizeOfRawData)

            for byte in data:
                pos += 1
                if byte == 0x00:
                    count += 1
                else:
                    if count > int(min_size):
                        raw_addr = section.PointerToRawData + pos - count -1
                        vir_addr = image_base + section.VirtualAddress + pos - count -1

                        print(f"[*] A code cave was found in section {section.Name.decode()}, raw address {raw_addr}, virtual address: {vir_addr} with the size {count} bytes. Permissions: {permissions}")
                    count = 0
    pe.close()
    file.close()

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('Syntax Invalid.')
        print('Use the following syntax: CodeCave <file name> <Min cave size>')
        sys.exit()

    file_name = sys.argv[1]
    min_size = sys.argv[2]

    find_cave(file_name, min_size)
