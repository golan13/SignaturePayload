import pefile
import argparse


def merge_data_into_file(file_path, data_path, new_name):
    print("[*] Parsing signed executable")
    pe = pefile.PE(file_path)
    data_directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    entry_security = [d for d in data_directory if d.name == 'IMAGE_DIRECTORY_ENTRY_SECURITY'][0]
    if entry_security.Size == 0:
        print("[*] No signature found in executable")
        print("[*] Exiting")
        return
    print("[*] Reading data to be written")
    data = open(data_path, 'rb')
    data_content = data.read()
    data_size = len(data_content)
    print("[*] Size of data to be written -", hex(data_size))
    new_signature_size = entry_security.Size + data_size
    print(f"[*] Changing signature size header from {hex(entry_security.Size)} to {hex(new_signature_size)}")
    print("[*] Old security directory:")
    print("\t", entry_security)
    data_directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    entry_security = [d for d in data_directory if d.name == 'IMAGE_DIRECTORY_ENTRY_SECURITY'][0]
    for d in data_directory:
        if d.name == 'IMAGE_DIRECTORY_ENTRY_SECURITY':
            d.Size = new_signature_size
    print("[*] New security directory:")
    print("\t", entry_security)
    pe.write(new_name)
    pe.close()
    print("[*] Writing data to file")
    with open(new_name, 'ab') as f:
        f.write(data_content)
    data.close()
    print("[*] Done")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('file', help='File with certificate to hide data', metavar='<file path>')
    parser.add_argument('data', help='Data to hide in file\'s certificate', metavar='<data path>')
    parser.add_argument('out', help='Name of output file', metavar='<output>')
    args = parser.parse_args()
    merge_data_into_file(args.file, args.data, args.out)


if __name__ == "__main__":
    main()
