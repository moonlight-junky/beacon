#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import pefile
import argparse
import struct

def main( f = None, o = None ):
    try:
        exe = pefile.PE( f );
        raw = exe.sections[0].get_data();
        end = raw.find(b'\xcc' * 4);
        raw = raw[:end]

        pub = open("publickey.bin", "rb+");
        key = pub.read(); 
        pub.close();

        if len( key ) != 0:
            raw = raw + key;
            raw = raw.replace( b'\x41' * 4, struct.pack('<I', len( key ) ));

        bin = open( o, 'wb+' );
        bin.write( raw );
        bin.close( );
    except Exception as e:
        print("[error]: {}".format(e));
        raise SystemExit

if __name__ in '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', help='Path to EXE file.', required=True);
    parser.add_argument('-o', help='Path to store code.', required=True);

    args = parser.parse_args();
    main(**vars(args));
