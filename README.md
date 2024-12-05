
# Usage Syntax
```
Usage: filehashbof C:\server123\somefile.txt md5
       filehashbof C:\server123\somefile.txt sha256
       filehashbof C:\server123\somefile.txt sha512
```

# CS Beacon Output

```
[03/28 09:09:06] beacon> filehashbof C:\Users\Administrator\Downloads\processhacker-2.39-bin.zip sha256
[03/28 09:09:06] [*] Running filehashbof [x86]
[03/28 09:09:07] [+] host called home, sent: 3610 bytes
[03/28 09:09:08] [+] received output:

_≡2AFB5303E191DDE688C5626C3EE545E32E52F09DA3B35B20F5E0D29A418432F5 	 sha256-hash	 C:\Users\Administrator\Downloads\processhacker-2.39-bin.zip
```

# Caveats
- Windows in FIPS-140 modes dont have MD5 algorithim available. Thus MD5 shouldnt work on those systems. 
- Hash output display is a bit ugly. TODO: Cleanup and verf string

# Credits
- Microsoft Help Forums
- BH Gang
