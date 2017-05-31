import sys
import struct
from PE_Header import PE_HEADER
from DotNet import DotNet, CLR_HEADER, METADATA_HEADER, RESOURCE_FILE


def main(target):
    print("[*] Loading...\n")
    exe = open(target, 'rb').read()
    pe_header = PE_HEADER(target)
    dotnet = DotNet(exe, pe_header.sections[0])
    functions = [0, 1, 2, 3, 4]
    print(
        "Functions\n",
        " 0) Exit\n",
        " 1) All\n",
        " 2) PE Header\n",
        " 3) .NET Directory\n",
        " 4) .NET Resources\n"
    )
    number = int(input("Select Function: "))
    if number == 0:
        sys.exit()
    elif number == 1:
        pe_header.show_all_headers()
        dotnet.show_all()
    elif number == 2:
        pe_header.show_all_headers()
    elif number == 3:
        dotnet.show_all()
    elif number == 4:
        resources = dotnet.get_resources()
        print(resources)
    else:
        print("Invalid Number")
        sys.exit()


if __name__ == '__main__':
    import sys
    if not sys.argv[1:]:
        print('PEAnalyzer.py target')
    else:
        main(sys.argv[1])
