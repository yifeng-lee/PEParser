import argparse
import sys
from peheader import *

def start():
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--version', action='version', version='version 0.0.1')
    parser.add_argument('-i', '--info',action="store_true", help='PE文件头信息')
    parser.add_argument('filename')
    args = parser.parse_args()
    return args

if __name__ == "__main__":
    args = start()
    if args.info or (len(sys.argv) == 2 and args.filename != None):
        d = {}
        r = open(args.filename,'rb')
        dosheader = r.read(0x40)
        ImageDosHeader = ImageDosHeader(dosheader)
        r.seek(ImageDosHeader.PEoffser(),0)
        ntheader = r.read(0xf0)
        ImageNtHeader = ImageNtHeader(ntheader)
        ImageNtHeader.show()