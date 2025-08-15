import r2pipe

FLAG_LEN = 39
XOR_KEY = 0x55
ADD_KEY = 0x0F

r2 = r2pipe.open("firmware", flags=["-2"])  # non-interactive
r2.cmd("aaa")

# Cari .rodata
sections = r2.cmdj("iSj")
rodata = next(s for s in sections if s["name"] == ".rodata")
addr = rodata["vaddr"]

# Ambil byte
r2.cmd(f"s {addr}")
enc = r2.cmdj(f"pxj {FLAG_LEN}")

# Fix: masking pakai & 0xFF untuk hindari nilai negatif
flag = ''.join(chr(((b - ADD_KEY) & 0xFF) ^ XOR_KEY) for b in enc)

print("Decoded flag:", flag)

