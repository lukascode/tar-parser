#!/usr/bin/env python3

import io
import os
import sys
import math
import json

class Tar:

    BLOCK_SIZE = 512

    def __init__(self, file_path):
        if not file_path or len(file_path) == 0:
            raise ValueError("Bad file path")
        self.file_path = file_path

    def __enter__(self):
        self.input_stream = open(self.file_path, "rb")
        self.headers = []
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def close(self):
        if self.input_stream:
            self.input_stream.close()
    
    def get_all_files(self):
        self.__scan()
        return list(map(
            lambda f: FileSnapshot(f.file_name, f.file_size, f.file_mode, f.flag), 
            self.headers
        ))

    def extract_file(self, file_name, target_folder=os.getcwd()):
        if not file_name or len(file_name) == 0:
            raise ValueError("Bad file name")
        if not target_folder or len(target_folder) == 0:
            raise ValueError("Bad target folder")
        self.__scan()
        result = list(filter(
            lambda fh: fh.flag == 0 and fh.file_name == file_name, 
            self.headers
        ))
        if len(result) == 0:
            raise RuntimeError("File '{}' not found".format(file_name))
        fh = result[0]
        leaf = os.path.basename(fh.file_name)
        f_path = os.path.join(target_folder, leaf)
        self.__extract(fh, f_path)

    def extract_all(self, target_folder=os.getcwd()):
        if not target_folder or len(target_folder) == 0:
            raise ValueError("Bad target folder")
        self.__scan()
        for fh in self.headers:
            f_path = os.path.join(target_folder, fh.file_name)
            if fh.flag == 5: # if directory
                os.makedirs(f_path, exist_ok=True)
            elif fh.flag == 0: # if regular file
                parent = os.path.dirname(os.path.abspath(f_path))
                os.makedirs(parent, exist_ok=True)
                self.__extract(fh, f_path)


    def __extract(self, fh, file_name):
        with open(file_name, "wb") as f:
            if fh.file_size > 0:
                total = 0
                bytes_left = fh.file_size
                self.input_stream.seek(fh.offset, 0)
                while bytes_left > 0:
                    data = self.input_stream.read(Tar.BLOCK_SIZE)
                    data = data[:bytes_left]
                    f.write(data)
                    bytes_left -= len(data)
    
    def __scan(self): # iterate over headers
        if len(self.headers) == 0:
            while True:
                block = self.input_stream.read(Tar.BLOCK_SIZE)
                if len(block) < Tar.BLOCK_SIZE:
                    break
                h = self.__get_file_header(block)
                if not len(h.magic) > 0:
                    break
                # ommit regular file bytes
                if h.flag == 0:
                    h.set_offset(self.input_stream.tell())
                    if h.file_size > 0:
                        if h.file_size % Tar.BLOCK_SIZE != 0:
                            bytes_to_skeep = math.ceil(h.file_size / Tar.BLOCK_SIZE) * Tar.BLOCK_SIZE
                        else:
                            bytes_to_skeep = h.file_size
                        self.input_stream.seek(bytes_to_skeep, 1)
                self.headers.append(h)

            
    def __get_file_header(self, block):
        try:
            file_name = self.__get_file_name(block)
            file_mode = self.__get_file_mode(block)
            uid = self.__get_uid(block)
            gid = self.__get_gid(block)
            file_size = self.__get_file_size(block)
            mtime = self.__get_mtime(block)
            chksum = self.__get_chksum(block)
            type_flag = self.__get_type_flag(block)
            linkname = self.__get_linkname(block)
            magic = self.__get_magic(block)
            version = self.__get_version(block)
            uname = self.__get_uname(block)
            gname = self.__get_gname(block)
            devmajor = self.__get_devmajor(block)
            devminor = self.__get_devminor(block)
            prefix = self.__get_prefix(block)
        except Exception as e:
            raise RuntimeError("Broken file") from e
        header = FileHeader(file_name, file_size, file_mode, uid, gid, 
            mtime, chksum, type_flag, linkname, magic, version, 
            uname, gname, devmajor, devminor, prefix)
        return header


    def __get_file_name(self, block): # string
        offset, size = 0, 100
        fname = self.__get_block_data(block, offset, size)
        fname = fname[0:fname.find(b'\x00')].decode().strip()
        return fname

    def __get_file_mode(self, block): # string
        offset, size = 100, 8
        mode = self.__get_block_data(block, offset, size)
        mode = mode[:mode.find(b'\x00')].decode().strip()
        return mode

    def __get_uid(self, block): # string
        offset, size = 108, 8
        uid = self.__get_block_data(block, offset, size)
        uid = uid[:uid.find(b'\x00')].decode().strip()
        return uid
    
    def __get_gid(self, block): # string
        offset, size = 116, 8
        gid = self.__get_block_data(block, offset, size)
        gid = gid[:gid.find(b'\x00')].decode().strip()
        return gid

    def __get_file_size(self, block): # int
        offset, size = 124, 12
        size = self.__get_block_data(block, offset, size)
        size = size[:size.find(b'\x00')].decode().strip()
        if len(size) > 0:
            size = int(size, 8)
        else:
            size = 0
        return size
    
    def __get_mtime(self, block): # int
        offset, size = 136, 12
        mtime = self.__get_block_data(block, offset, size)
        mtime = mtime[:len(mtime)-1]
        mtime = mtime[:mtime.find(b'\x00')].decode().strip()
        if len(mtime) > 0:
            mtime = int(mtime, 8)
        else:
            mtime = 0
        return mtime
    
    def __get_chksum(self, block): # int
        offset, size = 148, 8
        chksum = self.__get_block_data(block, offset, size)
        chksum = chksum[:chksum.find(b'\x00')].decode().strip()
        if len(chksum) > 0:
            chksum = int(chksum)
        else:
            chksum = 0
        return chksum

    def __get_type_flag(self, block): # int
        offset, size = 156, 1
        flag = self.__get_block_data(block, offset, size)
        if flag == b'\x00':
            flag = 0
        elif flag == b'x':
            flag = 11
        else:
            flag = int(flag)
        return flag

    def __get_linkname(self, block): # string (applicable if type_flag = 1 or 2)
        offset, size = 157, 100
        linkname = self.__get_block_data(block, offset, size)
        return linkname[:linkname.find(b'\x00')].decode().strip()

    def __get_magic(self, block): # string
        offset, size = 257, 6
        magic = self.__get_block_data(block, offset, size)
        magic = magic[:magic.find(b'\x00')].decode().strip()
        return magic

    def __get_version(self, block): # string
        offset, size = 263, 2
        version = self.__get_block_data(block, offset, size)
        version = version[:len(version)-1].decode().strip()
        return version

    def __get_uname(self, block): # string
        offset, size = 265, 32
        uname = self.__get_block_data(block, offset, size)
        uname = uname[:uname.find(b'\x00')].decode().strip()
        return uname
    
    def __get_gname(self, block): # string
        offset, size = 297, 32
        gname = self.__get_block_data(block, offset, size)
        gname = gname[:gname.find(b'\x00')].decode().strip()
        return gname
    
    def __get_devmajor(self, block): # string
        offset, size = 329, 8
        devmajor = self.__get_block_data(block, offset, size)
        devmajor = devmajor[:devmajor.find(b'\x00')].decode().strip()
        return devmajor
    
    def __get_devminor(self, block): # string
        offset, size = 337, 8
        devminor = self.__get_block_data(block, offset, size)
        devminor = devminor[:devminor.find(b'\x00')].decode().strip()
        return devminor

    def __get_prefix(self, block): # string
        offset, size = 345, 155
        prefix = self.__get_block_data(block, offset, size)
        prefix = prefix[:prefix.find(b'\x00')].decode().strip()
        return prefix

    def __get_block_data(self, block, offset, size):
        return block[offset:offset+size]

class FileSnapshot:
    def __init__(self, file_name, file_size, file_mode, flag):
        self.file_name = file_name
        self.file_size = file_size
        self.file_mode = file_mode
        self.flag = flag

    def __repr__(self):
        return self.file_name

class FileHeader:
    def __init__(self, file_name, file_size, file_mode, uid, gid, mtime, 
    chksum, flag, linkname, magic, version, uname, gname, devmajor, devminor, prefix):
        self.file_name = file_name
        self.file_size = file_size
        self.file_mode = file_mode
        self.uid = uid
        self.gid = gid
        self.mtime = mtime
        self.chksum = chksum
        self.flag = flag
        self.linkname = linkname
        self.magic = magic
        self.version = version
        self.uname = uname
        self.gname = gname
        self.devmajor = devmajor
        self.devminor = devminor
        self.prefix = prefix

    def set_offset(self, offset):
        self.offset = offset 
        

def usage():
    u = """
    Usage:
    tar.py <archive.tar> --list                 List all files in the archive
    tar.py <archive.tar> --extract-all          Extract all files from the archive
    tar.py <archive.tar> --extract <file>       Extract single file from the archive
    """
    print(u)
    sys.exit(1)

if __name__ == "__main__":
    try:
        if len(sys.argv) > 2:
            archive = sys.argv[1]
            operation = sys.argv[2]
            with Tar(archive) as t:
                if operation == "--list":
                    files = t.get_all_files()
                    for f in files:
                        print(f)
                elif operation == "--extract-all":
                    t.extract_all()
                elif operation == "--extract":
                    if len(sys.argv) > 3:
                        file_name = sys.argv[3]
                        t.extract_file(file_name)
                    else:
                        usage()
        else:
            usage()
    except Exception as e:
        print("Error: {}".format(str(e)))
        sys.exit(1)