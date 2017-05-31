import struct
from Structure import Structure
from PE_Header import IMAGE_SECTION_HEADER


class CLR_HEADER(Structure):
    _format = (
        'I', 'H', 'H', 'I', 'I', 'I', 'I', 'I', 'I', 'I', 'I', 'I', 'I', 'I',
        'I', 'I', 'I', 'I', 'I'
    )
    _member_name = (
        'HeaderSize', 'MajorRuntimeVersion', 'MinorRuntimeVersion',
        'MetaDataDirectoryAddress', 'MetaDataDirectorySize', 'Flags',
        'EntryPointToken', 'ResourcesDirectoryAddress',
        'ResourcesDirectorySize', 'StrongNameSignatureAddress',
        'StrongNameSignatureSize', 'CodeManagerTableAddress',
        'CodeManagerTableSize', 'VTableFixupsAddress', 'VTableFixupsSize',
        'ExportAddressTableJumpsAddress', 'ExportAddressTableJumpsSize',
        'ManagedNativeHeaderAddress', 'ManagedNativeHeaderSize'
    )
    _size = 0x48

    def __init__(self, attr):
        self.member = attr

    def show_member(self):
        print("CLR_HEADER")
        super().show_member()


class METADATA_HEADER(Structure):
    _format = (
        'I', 'H', 'H', 'I', 'I', 's', 'H', 'H'
    )
    _member_name = (
        'Signature', 'MajorVersion', 'MinorVersion', 'Reserved1',
        'VersionStringLength', 'VersionString', 'Flags', 'NumberOfStreams'
    )
    _size = 0x14

    def __init__(self, exe, offset):
        format = 'IHHII'
        self.member = struct.unpack_from("<"+format, exe, offset)
        version_length = self.get_attr('VersionStringLength')
        format = 'IHHII' + str(version_length) + 's' + 'HH'
        self.member = struct.unpack_from("<"+format, exe, offset)

    def show_member(self):
        print("METADATA_HEADER")
        super().show_member()


class RESOURCE_FILE(Structure):
    _format = (
        'I', 'I', 'I', 's', 'I', 'I', 'I'
    )
    _member_name = (
        'Signature', 'NumberOfReaders', 'SizeOfReaderTypes', 'ReaderName',
        'ResourceFileVersion', 'NumberOfActualResources',
        'NumberOfResourceTypes'
    )

    def __init__(self, exe, address):
        self.address = address
        format = 'III'
        self.member = struct.unpack_from("<"+format, exe, address + 0x04)
        version_length = self.get_attr('SizeOfReaderTypes')
        format = 'III' + str(version_length) + 's' + 'III'
        self.member = struct.unpack_from("<"+format, exe, address + 0x04)
        self._size = 4*6 + version_length + 0x04

    def show_member(self):
        print("RESOURCE_FILE")
        super().show_member()


class DotNet(Structure):
    _iat_size = 0x8
    _padding = 0x7  # PADPADP
    _dword = 0x04

    def __init__(self, exe, text_section):
        self.exe = exe
        section_offset = text_section.get_attr('PointerToRawData')
        format = CLR_HEADER.get_format_string(CLR_HEADER._format)
        self.clr_header = CLR_HEADER(struct.unpack_from("<"+format, exe, section_offset+self._iat_size))

        rva = text_section.get_attr('VirtualAddress')
        metadata_address = self.clr_header.get_attr('MetaDataDirectoryAddress') - rva + section_offset
        self.metadata_header = METADATA_HEADER(exe, metadata_address)

        resource_address = self.clr_header.get_attr('ResourcesDirectoryAddress') - rva + section_offset
        self.resource_file = RESOURCE_FILE(exe, resource_address)

    def get_resources(self):
        addr = self.resource_file.address + self.resource_file._size
        addr += self._padding
        hash_values = []
        offsets = []
        resource_number = self.resource_file.get_attr('NumberOfActualResources')
        for i in range(0, resource_number):
            hash_values.append(struct.unpack_from("<I", self.exe, addr)[0])
            addr += 0x4
        for i in range(0, resource_number):
            offsets.append(struct.unpack_from("<I", self.exe, addr)[0])
            addr += 0x4
        addr += 0x4  # 0x3f4 = 0x105
        resource_names = []
        resource_values = []
        for i in range(0, resource_number):
            resource_length = struct.unpack_from("<B", self.exe, addr)[0]
            addr += 0x1
            resource = struct.unpack_from("<" + "H"*int(resource_length/2), self.exe, addr)
            resource_names.append(self.decode_resource(resource))
            addr += resource_length + 0x4
        for i in range(0, resource_number):
            addr += 0x1
            resource_length = struct.unpack_from("<B", self.exe, addr)[0]
            addr += 0x1
            resource = struct.unpack_from("<" + "B"*resource_length, self.exe, addr)
            resource_values.append(self.decode_resource(resource))
            addr += resource_length
        resources = {}
        for i in range(0, resource_number):
            resources[resource_names[i]] = resource_values[i]
        return resources

    def decode_resource(self, resource):
        result = ""
        for r in resource:
            result += str(chr(r))
        return result

    def show_all(self):
        print(".NET")
        self.clr_header.show_member()
        self.metadata_header.show_member()
        self.resource_file.show_member()
