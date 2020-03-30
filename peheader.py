import sys
import time


class ImageDosHeader:
    def __init__(self, dosHeader):
        self.e_magic = dosHeader[0x0:0x2]
        self.e_lfanew = dosHeader[0x3c:0x3f]
        if self.e_magic != b'MZ':
            print("this is not PE program!")
            exit(-1)

    def PEoffser(self):
        return (int.from_bytes(self.e_lfanew, byteorder='little'))


class ImageFileHeader():
    def __init__(self, fileHeader):
        self.machine = fileHeader[0x4:0x6]
        self.numberOfSections = fileHeader[0x6:0x8]
        self.timeDateStamp = fileHeader[0x8:0xc]
        self.sizeOfOptionalHeader = fileHeader[0x14:0x16]
        self.characteristics = fileHeader[0x16:0x18]

    def CPUtype(self):
        types = {
            0x14c: 'Intel i386',
            0x162: 'MIPS R3000',
            0x166: 'MIPS R4000',
            0x184: 'Alpha AXP',
            0x1f0: 'Power PC'
        }
        try:
            return types[int.from_bytes(self.machine, 'little')]
        except KeyError:
            print('CPUtypeError!')
            exit(-1)

    def Time(self):
        return time.strftime(
            "%Y-%m-%d %H:%M:%S",
            time.localtime(int.from_bytes(self.timeDateStamp, 'little')))

    def Version(self):
        v = {0xe0: 'PE32', 0xf0: 'PE32+'}
        try:
            return v[int.from_bytes(self.sizeOfOptionalHeader, 'little')]
        except KeyError:
            print('versionError!')
            exit(-1)


class ImageOptionalHeader():
    def __init__(self, optionalHeader, version):
        if version == 'PE32':
            self.magic = optionalHeader[0x18:0x1a]
            self.sizeOfCode = optionalHeader[0x1c:0x20]
            self.sizeOfInitializedData = optionalHeader[0x20:0x24]
            self.sizeOfUninitializedData = optionalHeader[0x24:0x28]
            self.addressOfEntryPoint = optionalHeader[0x28:0x2c]  # 入口RVA
            self.baseOfCode = optionalHeader[0x2c:0x30]  # 代码段RVA
            self.baseOfData = optionalHeader[0x30:0x34]  # 数据段RVA
            self.imageBase = optionalHeader[0x34:0x38]  # 基址
            self.sectionAlignment = optionalHeader[0x38:0x3c]  # 文件中内存的对齐值
            self.fileAlignment = optionalHeader[0x3c:0x40]  # 文件中区块的对齐值
            self.sizeOfImage = optionalHeader[0x50:0x54]  # 映像载入内存后的大小
            self.sizeOfHeaders = optionalHeader[0x54:0x58]  # 首部大小
            self.checkSum = optionalHeader[0x58:0x5b]  # 校验和
            self.subSystem = optionalHeader[0x5c:0x5e]  # 文件子系统
            self.numberOfRvaAndSizes = optionalHeader[0x74:0x78]  # 数据目录表项数
        elif version == 'PE32+':
            self.magic = optionalHeader[0x18:0x1a]
            self.sizeOfCode = optionalHeader[0x1c:0x20]
            self.sizeOfInitializedData = optionalHeader[0x20:0x24]
            self.sizeOfUninitializedData = optionalHeader[0x24:0x28]
            self.addressOfEntryPoint = optionalHeader[0x28:0x2c]  # 入口RVA
            self.baseOfCode = optionalHeader[0x2c:0x30]  # 代码段RVA
            self.baseOfData = optionalHeader[0x30:0x34]  # 数据段RVA
            self.imageBase = optionalHeader[0x30:0x38]  # 基址
            self.sectionAlignment = optionalHeader[0x38:0x3c]  # 文件中内存的对齐值
            self.fileAlignment = optionalHeader[0x3c:0x40]  # 文件中区块的对齐值
            self.sizeOfImage = optionalHeader[0x50:0x54]  # 映像载入内存后的大小
            self.sizeOfHeaders = optionalHeader[0x54:0x58]  # 首部大小
            self.checkSum = optionalHeader[0x58:0x5b]  # 校验和
            self.subSystem = optionalHeader[0x5c:0x5e]  # 文件子系统
            self.numberOfRvaAndSizes = optionalHeader[0x84:0x88]  # 数据目录表项数
            self.baseOfData = 0x0
        else:
            print('error!')
            exit(-1)

    def Magic(self):
        return int.from_bytes(self.magic, 'little')

    def SubSystem(self):
        types = {
            0: '未知',
            1: '本地',
            2: 'Windows图形界面',
            3: 'Windows控制台',
            5: 'OS/2控制台',
            7: 'POSIX控制台',
            8: '保留',
            9: 'Windows CE图形界面'
        }
        try:
            return types[int.from_bytes(self.subSystem, 'little')]
        except KeyError:
            return types[0]


class ImageNtHeader(ImageFileHeader, ImageOptionalHeader):
    def __init__(self, ntHeader):
        ImageFileHeader.__init__(self, ntHeader)
        ImageOptionalHeader.__init__(self, ntHeader, self.Version())
        self.signature = ntHeader[0:0x4]
        if self.signature != b'PE\x00\x00':
            print("this is not PE program!")
            exit(-1)

    def show(self):
        print('入口点:    %08x' %
              int.from_bytes(self.addressOfEntryPoint, 'little'))
        print('镜像大小:  %08x' % int.from_bytes(self.sizeOfImage, 'little'))
        if self.Version() == 'PE32':
            print('基地址:    %08x' % int.from_bytes(self.imageBase, 'little'))
        else:
            print('基地址:    %016x' % int.from_bytes(self.imageBase, 'little'))
        print('代码基址:  %08x' % int.from_bytes(self.baseOfCode, 'little'))
        print('数据基址:  %08x' % int.from_bytes(self.baseOfData, 'little'))
        print('内存块对齐:%08x' % int.from_bytes(self.sectionAlignment, 'little'))
        print('文件块对齐:%08x' % int.from_bytes(self.fileAlignment, 'little'))
        print('标志字:    %08x' % int.from_bytes(self.magic, 'little'))
        print('子系统:    %08x(%s)' %
              (int.from_bytes(self.subSystem, 'little'), self.SubSystem()))
        print('区段数目:  %08x' % int.from_bytes(self.numberOfSections, 'little'))
        print('日期:      %08x(%s)' %
              (int.from_bytes(self.timeDateStamp, 'little'), self.Time()))
        print('首部大小:  %08x' % int.from_bytes(self.sizeOfHeaders, 'little'))
        print('特征值:    %08x' %
              (int.from_bytes(self.characteristics, 'little')))
        print('校验和:    %08x' % int.from_bytes(self.checkSum, 'little'))
        print('可选头大小:%08x' %
              int.from_bytes(self.sizeOfOptionalHeader, 'little'))
        print('RVA项数:   %08x' %
              int.from_bytes(self.numberOfRvaAndSizes, 'little'))
