MAGIC CHECK

MAGIC CHECK is a lightweight Python CLI tool that verifies a file’s *real* type using magic bytes instead of trusting file extensions.

It answers one simple question:
Is this file actually what it claims to be?

WHAT IT DOES
MAGIC CHECK reads the first bytes of a file (magic numbers) and compares them against known signatures to determine the true file type.

For each file, it reports whether the extension:

[OK] matches the detected type  
[MISMATCH] mismatches the detected type  
[UNKNOWN TYPE]  has no recognizable magic signature  
⚠️ shows suspicious characteristics (executables disguised as images, archives posing as documents, etc.)


USE CASES

File integrity checks  
Media library audits  
Investigating suspicious files  
Learning how file signatures actually work  


REQUIREMENTS

Python *3.8+*

Works on *Windows* and *Linux* (Currently tested on Windows 11 and Parrot OS)

No external dependencies
# USAGE
Run the script directly with Python:
```bash
python magic_check.py [options] <path> [path ...]

Show help
python magic_check.py -h

Example usage (WINDOWS CMD)
python magic_check.py -r --summary F:\

Example usage (Linux Terminal)
python magic_check.py -r --summary /path/to/folder

Compute SHA-256 hashes
python magic_check.py --hash suspicious_folder

## OUTPUT STATUS MEANINGS
OK - File extension matches detected magic type
MISMATCH - Extension does not match actual file type
UNKNOWN TYPE - No known magic signature detected
NO EXTENSION - File has no extension

## SUPPORTED FILE TYPES
NOTE: Please understand this is a tool under continuing development and a lot of file types are not yet built into the tool.
- Images: JPEG, PNG, GIF, BMP
- Documents / Data: PDF, OLE2 (legacy Office, SQLite
- Archives: ZIP, RAR, 7z, GZIP, BZIP2, XZ, AR (.deb)
- Media: MP3, FLAC, OGG, MP4/QuickTime, MKV/WebM
- Executables: Windows PE, ELF, Mach-O
Unknown formats are reported explicitly as 'UNKNOWN TYPE'.

Author James Reeves @l3ssth4nz3r0k00l
