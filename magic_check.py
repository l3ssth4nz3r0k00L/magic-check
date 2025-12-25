#!/usr/bin/env python3

# ANSI color codes for styling (used only when color is enabled)
PURPLE = "\033[35m"
YELLOW = "\033[33m"
GREEN  = "\033[32m"
RED    = "\033[31m"
CYAN   = "\033[36m"
RESET  = "\033[0m"

# Bright lime-ish green for the footer
LIME   = "\033[92m"

FOOTER = (
    "\n"
    + LIME + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + RESET + "\n"
    + LIME + "  The Spell Is Complete. Truth Is Revealed." + RESET + "\n"
    + LIME + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + RESET + "\n"
)

BANNER = (
    PURPLE +
    r"""
                ███╗   ███╗     █████╗      ██████╗     ██╗     ██████╗     
                ████╗ ████║    ██╔══██╗    ██╔════╝     ██║    ██╔════╝    
                ██╔████╔██║    ███████║    ██║  ███╗    ██║    ██║     
                ██║╚██╔╝██║    ██╔══██║    ██║   ██║    ██║    ██║      
                ██║ ╚═╝ ██║    ██║  ██║    ╚██████╔╝    ██║    ╚██████╗     
                ╚═╝     ╚═╝    ╚═╝  ╚═╝     ╚═════╝     ╚═╝     ╚═════╝     

                 ██████╗    ██╗  ██╗    ███████╗     ██████╗    ██╗  ██╗
                ██╔════╝    ██║  ██║    ██╔════╝    ██╔════╝    ██║ ██╔╝
                ██║         ███████║    █████╗      ██║         █████╔╝ 
                ██║         ██╔══██║    ██╔══╝      ██║         ██╔═██╗ 
                ╚██████╗    ██║  ██║    ███████╗    ╚██████╗    ██║  ██╗
                 ╚═════╝    ╚═╝  ╚═╝    ╚══════╝     ╚═════╝    ╚═╝  ╚═╝
    """ +
    RESET +
"\n" +
YELLOW +
r"            🔮  v0.1.0  |  Conjured by James Reeves (@" + PURPLE + r"l3ssth4nz3r0k00L" + YELLOW + r")  🔮" +
RESET + "\n" +
YELLOW +
r"                   ✨ 🔮  M A G I C   C H E C K  🔮 ✨" +
RESET + "\n" +
PURPLE +
r"                        *" + YELLOW + "   ." + PURPLE + "    ✦" + YELLOW + "   ." + PURPLE + "   ✧" + YELLOW + "   *" +
RESET + "\n" +
YELLOW +
r"                    <°)))><   " + PURPLE + " ASCII Wizardry" + "\n" +
YELLOW +
r"                     \__/    " + PURPLE + " File-Type Sorcery ✨" +
RESET +
"\n"
)



import sys
import os
import argparse
import hashlib
from typing import Optional, Tuple, List

# Expanded magic numbers (file signatures)
MAGIC_NUMBERS = {
    # --- Images ---
    b"\xFF\xD8\xFF": "JPEG image",
    b"\x89PNG\r\n\x1a\n": "PNG image",
    b"GIF87a": "GIF image",
    b"GIF89a": "GIF image",
    b"BM": "BMP image",
    # RIFF is a generic container used by WAV, AVI, WebP, etc.
    b"RIFF": "RIFF container (WAV/AVI/WebP/etc)",

    # --- Documents / Data ---
    b"%PDF-": "PDF document",
    b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1": "OLE2 container (legacy DOC/XLS/PPT, etc.)",
    b"SQLite format 3\x00": "SQLite 3 database",

    # --- Archives / Compressed ---
    b"PK\x03\x04": "ZIP archive / DOCX / XLSX / PPTX / JAR / APK / ODF",
    b"Rar!\x1A\x07\x00": "RAR archive (v1.5)",
    b"Rar!\x1A\x07\x01\x00": "RAR archive (v5)",
    b"7z\xBC\xAF\x27\x1C": "7-Zip archive",
    b"\x1F\x8B\x08": "GZIP compressed file",
    b"BZh": "Bzip2 compressed file",
    b"\xFD7zXZ\x00": "XZ compressed file",
    b"!<arch>\n": "AR archive (used by .deb packages)",

    # --- Audio / Media ---
    b"ID3": "MP3 audio (ID3 tag)",
    b"\xFF\xFB": "MPEG audio (MP3 frame)",
    b"fLaC": "FLAC audio",
    b"OggS": "Ogg container (Vorbis/Opus/etc.)",

    # --- Video / Containers ---
    b"\x1A\x45\xDF\xA3": "Matroska container (MKV/WebM)",
    b"\x00\x00\x00\x18ftyp": "MP4/QuickTime container (ISO BMFF)",

    # --- Executables / Binaries ---
    b"MZ": "Windows/DOS executable (PE/EXE/DLL)",
    b"\x7fELF": "ELF executable (Linux/Unix)",
    b"\xFE\xED\xFA\xCE": "Mach-O executable (32-bit, big-endian)",
    b"\xFE\xED\xFA\xCF": "Mach-O executable (64-bit, big-endian)",
    b"\xCE\xFA\xED\xFE": "Mach-O executable (32-bit, little-endian)",
    b"\xCF\xFA\xED\xFE": "Mach-O executable (64-bit, little-endian)",

    # --- MPEG / Streams ---
    b"\x00\x00\x01\xBA": "MPEG Program Stream",
    b"\x00\x00\x01\xB3": "MPEG Video Stream",
}

MAX_MAGIC_LEN = max(len(sig) for sig in MAGIC_NUMBERS.keys())


def read_magic_bytes(path: str) -> Optional[bytes]:
    """Read the first MAX_MAGIC_LEN bytes from a file."""
    try:
        with open(path, "rb") as f:
            return f.read(MAX_MAGIC_LEN)
    except (OSError, PermissionError) as e:
        print(f"[!] Could not read {path}: {e}")
        return None


def identify_type(magic: Optional[bytes]) -> Optional[str]:
    """Return a detected file type string or None if no signature matches."""
    if magic is None:
        return None

    for signature, filetype in MAGIC_NUMBERS.items():
        if magic.startswith(signature):
            return filetype

    return None


def get_extension(path: str) -> str:
    """Return the file extension without leading dot, lowercase."""
    _, ext = os.path.splitext(path)
    return ext[1:].lower() if ext else ""


def ext_matches_detected(ext: str, detected: str) -> bool:
    """Return True if the extension reasonably matches the detected type."""
    if not ext or not detected:
        return False

    ext = ext.lower()
    d = detected.lower()

    # Simple case: the extension text appears in the detected description
    if ext in d:
        return True

    # Treat .jpg / .jpeg / .jfif as the same family
    if ext in {"jpg", "jpeg", "jfif"} and "jpeg" in d:
        return True

    # ZIP-based container formats (OOXML + ODF + some others)
    zip_container_exts = {
        "zip",
        "jar",
        "apk",
        "docx",
        "xlsx",
        "pptx",
        "odt",
        "ods",
        "odp",
    }

    if ext in zip_container_exts and "zip" in d:
        return True

    return False


def analyze_file(path: str) -> Tuple[str, Optional[str], str]:
    """
    Analyze a single file.

    Returns (path, detected_type, extension).
    detected_type may be None if unknown.
    """
    magic = read_magic_bytes(path)
    detected_type = identify_type(magic)
    ext = get_extension(path)
    return path, detected_type, ext


def walk_paths(target: str, recursive: bool) -> List[str]:
    """
    Return a list of files under the given target.

    If target is a file, return [target].
    If target is a directory:
      - If recursive is False: only direct children
      - If recursive is True: walk all subdirectories
    """
    if os.path.isfile(target):
        return [target]

    if os.path.isdir(target):
        files: List[str] = []
        if recursive:
            for root, _, filenames in os.walk(target):
                for name in filenames:
                    files.append(os.path.join(root, name))
        else:
            for name in os.listdir(target):
                full = os.path.join(target, name)
                if os.path.isfile(full):
                    files.append(full)
        return files

    print(f"[!] {target} is not a valid file or directory")
    return []


def compute_sha256(path: str) -> Optional[str]:
    """Compute SHA-256 hash of a file."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError) as e:
        print(f"[!] Could not hash {path}: {e}")
        return None


def detect_suspicious(detected: Optional[str], ext: str) -> Optional[str]:
    """
    Return a human-readable suspicious pattern message, or None if nothing stands out.
    """
    ext = ext.lower() if ext else ""
    desc = detected.lower() if detected else ""

    image_exts = {"jpg", "jpeg", "jfif", "png", "gif", "bmp", "webp"}
    doc_exts = {"txt", "log", "rtf", "pdf", "doc", "docx", "odt", "ods", "odp"}
    exec_exts = {"exe", "dll", "bin", "so"}
    script_exts = {"sh", "ps1", "bat", "cmd", "vbs", "js", "py", "rb", "pl"}

    # Formats that are *expected* to be ZIP-based containers
    benign_zip_containers = {
        "docx", "xlsx", "pptx",
        "odt", "ods", "odp",
        "jar", "apk",
    }

    is_executable = "executable" in desc
    is_archive = any(word in desc for word in ["archive", "compressed", "7-zip", "gzip", "bzip", "xz"])

    # 1) Executable pretending to be something harmless
    if is_executable and ext in image_exts.union(doc_exts):
        return f"Executable file disguised as .{ext}"

    # 2) Executable with no extension at all
    if is_executable and not ext:
        return "Executable file with no extension"

    # 3) Archive pretending to be a document or image (but NOT legit containers)
    if is_archive and ext in image_exts.union(doc_exts) and ext not in benign_zip_containers:
        return f"Archive file disguised as .{ext}"

    # 4) Exec / script-style extension but no known magic at all
    if not detected and ext in exec_exts.union(script_exts):
        return f"File has executable/script-style extension '.{ext}' but no known signature"

    # 5) Otherwise, don't scream about generic unknowns
    return None


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Magic Check - File Type Sorcery Tool: verify real file types using magic bytes."
    )
    parser.add_argument(
        "paths",
        nargs="+",
        help="File(s) or directory(ies) to analyze.",
    )
    parser.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        help="Recursively scan directories.",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print a summary of status counts after scanning.",
    )
    parser.add_argument(
        "--hash",
        action="store_true",
        help="Compute SHA-256 hash for each file.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors and banner for clean output.",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    # Gather files to analyze
    targets = args.paths
    files_to_check: List[str] = []

    for target in targets:
        files_to_check.extend(walk_paths(target, recursive=args.recursive))

    if not files_to_check:
        print("[!] No valid files to analyze.")
        sys.exit(1)

    # Configure color usage
    if args.no_color:
        green = red = yellow = cyan = reset = ""
        show_banner = False
    else:
        green, red, yellow, cyan, reset = GREEN, RED, YELLOW, CYAN, RESET
        show_banner = True

    # Print the banner once at the top (unless suppressed)
    if show_banner:
        print(BANNER)

    # Summary counters
    total = 0
    ok_count = 0
    mismatch_count = 0
    unknown_count = 0
    noext_count = 0

    for path in files_to_check:
        path, detected, ext = analyze_file(path)
        total += 1

        # Determine status + note
        if detected is None:
            status = "UNKNOWN TYPE"
            note = ""
            unknown_count += 1
        else:
            if ext == "":
                status = "NO EXTENSION"
                note = "Consider adding one."
                noext_count += 1
            elif ext_matches_detected(ext, detected):
                status = "OK"
                note = ""
                ok_count += 1
            else:
                status = "MISMATCH"
                note = f"extension '.{ext}' vs magic: {detected}"
                mismatch_count += 1

        # Pick a color based on status
        if status == "OK":
            color = green
        elif status == "MISMATCH":
            color = red
        elif status == "UNKNOWN TYPE":
            color = yellow
        elif status == "NO EXTENSION":
            color = cyan
        else:
            color = reset

        # Status line
        print(f"{color}[{status}]{reset} {path}")

        # Detail lines
        if detected:
            print(f"    Detected : {detected}")
        else:
            print("    Detected : Unknown (no magic match)")

        if ext:
            print(f"    Extension: .{ext}")
        else:
            print("    Extension: <none>")

        if note:
            print(f"    Note     : {note}")

        # Suspicious pattern detection
        suspicious_msg = detect_suspicious(detected, ext)
        if suspicious_msg:
            warn_prefix = "⚠ Suspicious"
            warn_color = red if not args.no_color else ""
            print(f"{warn_color}    {warn_prefix}: {suspicious_msg}{reset}")

        # Optional SHA-256 hash
        if args.hash:
            file_hash = compute_sha256(path)
            if file_hash:
                print(f"    SHA256   : {file_hash}")

        print()
    
    if args.summary:
        print("Summary:")
        print(f"  Total files   : {total}")
        print(f"  OK            : {ok_count}")
        print(f"  MISMATCH      : {mismatch_count}")
        print(f"  UNKNOWN TYPE  : {unknown_count}")
        print(f"  NO EXTENSION  : {noext_count}")
        print()

    print( FOOTER )

if __name__ == "__main__":
    main()

