import struct
from Structure import Structure


class IMAGE_DOS_HEADER(Structure):
    _format = (
        'H', 'H', 'H', 'H', 'H', 'H', 'H', 'H', 'H', 'H', 'H', 'H', 'H',
        'H', '8s', 'H', 'H', '20s', 'I'
    )
    _member_name = (
        'e_magic', 'e_cblp', 'e_cp', 'e_crlc', 'e_cparhdr', 'e_minalloc',
        'e_maxalloc', 'e_ss', 'e_sp', 'e_csum', 'e_ip', 'e_cs', 'e_lfarlc',
        'e_ovno', 'e_res', 'e_oemid', 'e_oeminfo', 'e_res2', 'e_lfanew'
    )
    _size = 0x40

    def __init__(self, attr):
        self.member = attr

    def show_member(self):
        print("DOS_HEADER")
        super().show_member()


class IMAGE_FILE_HEADER(Structure):
    _format = (
        'H', 'H', 'I', 'I', 'I', 'H', 'H'
    )
    _member_name = (
            'Machine', 'NumberOfSections', 'TimeDateStamp',
            'PointerToSymbolTable', 'NumberOfSymbols', 'SizeOfOptionalHeader',
            'Characteristics'
    )
    _size = 0x14

    def __init__(self, attr):
        self.member = attr

    def show_member(self):
        print("FILE_HEADER")
        super().show_member()

class IMAGE_OPTIONAL_HEADER(Structure):
    _format = (
        'H', 'B', 'B', 'I', 'I', 'I', 'I', 'I', 'I', 'I', 'I', 'I', 'H',
        'H', 'H', 'H', 'H', 'H', 'I', 'I', 'I', 'I', 'H', 'H', 'I', 'I',
        'I', 'I', 'I', 'I', '128s'
    )
    _member_name = (
        'Magic', 'MajorLinkerVersion', 'MinorLinkerVersion', 'SizeOfCode',
        'SizeOfInitializedData', 'SizeOfUninitializedData',
        'AddressOfEntryPoint', 'BaseOfCode', 'BaseOfData', 'ImageBase',
        'SectionAlignment', 'FileAlignment', 'MajorOperatingSystemVersion',
        'MinorOperatingSystemVersion', 'MajorImageVersion',
        'MinorImageVersion', 'MajorSubsystemVersion',
        'MinorSubsystemVersion', 'Win32VersionValue', 'SizeOfImage',
        'SizeOfHeaders', 'CheckSum', 'Subsystem', 'DllCharacteristics',
        'SizeOfStackReserve', 'SizeOfStackCommit', 'SizeOfHeapReserve',
        'SizeOfHeapCommit', 'LoaderFlags', 'NumberOfRvaAndSizes',
        'DataDirectory[16]'
    )
    _size = 0xe0

    def __init__(self, attr):
        self.member = attr
        self.data_direcotory = self.get_data_directory()

    def show_member(self):
        print("OPTIONAL_HEADER")
        super().show_member()
        self.show_data_directory()

    def get_data_directory(self):
        all_directory = self.member[len(self._member_name) - 1]
        directory = []
        for i in range(0, 16):
            directory.append(IMAGE_DATA_DIRECTORY(struct.unpack_from("II", all_directory, 8*i)))
        return directory

    def show_data_directory(self):
        for (index, data) in enumerate(self.data_direcotory):
            if data.member[0] != 0x0 and data.member[1] != 0x0:
                print("DATA_DIRECTORY[{}]".format(index))
                data.show_member()



class IMAGE_NT_HEADERS(Structure):
    _format = (
        'I',
        IMAGE_FILE_HEADER.get_format_string(IMAGE_FILE_HEADER._format),
        IMAGE_OPTIONAL_HEADER.get_format_string(IMAGE_OPTIONAL_HEADER._format)
    )
    _member_name = (
        'Signature', 'FileHeader', 'OptionalHeader'
    )
    _size = 0xf8

    def __init__(self, attr):
        self.member = attr

    def show_member(self):
        print("NT_HEADERS")
        super().show_member()

class IMAGE_DATA_DIRECTORY(Structure):
    _format = ('I', 'I')
    _member_name = ('VirtualSize', 'Size')
    _size = 0x08

    def __init__(self, attr):
        self.member = attr

    def show_member(self):
        super().show_member()


class IMAGE_SECTION_HEADER(Structure):
    _format = (
        'Q', 'I', 'I', 'I', 'I', 'I', 'I', 'H', 'H', 'I'
    )
    _member_name = (
        'Name', 'VirtualSize', 'VirtualAddress', 'SizeOfRawData',
        'PointerToRawData', 'PointerToRelocations', 'PointerToLinenumbers',
        'NumberOfRelocations', 'NumberOfLinenumbers', 'Characteristics'
    )
    _size = 0x28

    def __init__(self, attr):
        self.member = attr

    def show_member(self):
        print("SECTION")
        super().show_member()


class PE_HEADER():

    def __init__(self, exe):
        self.exe = open(exe, 'rb').read()
        self.set_dos_header()
        self.set_nt_header()
        self.set_section_headers()
        self.size = self.optional_header.get_attr('SizeOfCode')

    def set_dos_header(self):
        format = IMAGE_DOS_HEADER.get_format_string(IMAGE_DOS_HEADER._format)
        self.dos_header = IMAGE_DOS_HEADER(struct.unpack_from("<"+format, self.exe, 0))

    def set_nt_header(self):
        NT_HEADERS_OFFSET = self.dos_header.get_attr('e_lfanew')
        FILE_HEADER_OFFSET = NT_HEADERS_OFFSET + 0x04
        OPTIONAL_HEADER_OFFSET = NT_HEADERS_OFFSET + 0x18

        format = IMAGE_NT_HEADERS.get_format_string(IMAGE_NT_HEADERS._format)
        self.nt_header = IMAGE_NT_HEADERS(struct.unpack_from("<"+format, self.exe, NT_HEADERS_OFFSET))

        format = IMAGE_FILE_HEADER.get_format_string(IMAGE_FILE_HEADER._format)
        self.file_header = IMAGE_FILE_HEADER(struct.unpack_from("<"+format, self.exe, FILE_HEADER_OFFSET))

        format = IMAGE_OPTIONAL_HEADER.get_format_string(IMAGE_OPTIONAL_HEADER._format)
        self.optional_header = IMAGE_OPTIONAL_HEADER(struct.unpack_from("<"+format, self.exe, OPTIONAL_HEADER_OFFSET))

    def set_section_headers(self):
        NT_HEADERS_OFFSET = self.dos_header.get_attr('e_lfanew')
        FILE_HEADER_OFFSET = NT_HEADERS_OFFSET + 0x04
        OPTIONAL_HEADER_OFFSET = NT_HEADERS_OFFSET + 0x18
        FIRST_SECTION_OFFSET = OPTIONAL_HEADER_OFFSET + IMAGE_OPTIONAL_HEADER._size
        section_number = self.file_header.get_attr('NumberOfSections')
        self.sections = []
        for i in range(0, section_number):
            format = IMAGE_SECTION_HEADER.get_format_string(IMAGE_SECTION_HEADER._format)
            offset = FIRST_SECTION_OFFSET + i*IMAGE_SECTION_HEADER._size
            section = IMAGE_SECTION_HEADER(struct.unpack_from("<" + format, self.exe, offset))
            self.sections.append(section)

    def get_section(self, name):
        return

    def show_all_headers(self):
        self.dos_header.show_member()
        self.nt_header.show_member()
        self.file_header.show_member()
        self.optional_header.show_member()
        self.show_all_sections()

    def show_all_sections(self):
        for section in self.sections:
            section.show_member()
