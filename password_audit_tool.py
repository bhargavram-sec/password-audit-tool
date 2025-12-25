"""
Password Audit & Recovery Tool

DISCLAIMER:
This tool is intended strictly for educational purposes,
digital forensics labs, and authorized password recovery.
Use only on systems and files you own or have explicit permission to test.
The author is not responsible for misuse.
"""

__author__ = "Bhargav Ram"
__version__ = "1.0"
__license__ = "MIT"


DEFAULT_WORDLIST_PATH = None
import msoffcrypto
import hashlib
import itertools
import json
import os
import re
import string
import sys
import time
import zipfile
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, Dict, List

# ----- CONFIGURATION -----
PROGRESS_FILE = Path.home() / ".enhanced_cracker_progress.json"
REPORT_FILE   = Path.home() / ".enhanced_cracker_report.json"
MAX_DICTIONARY_ATTEMPTS_SESSION = 10_000_000
MAX_BRUTE_COMBINATIONS = 1_000_000_000
PRINT_INTERVAL = 2_000
SPECIAL_CHARS = "!@#$%^&*()-_+=[]{};:,.<>/?\\|`~"
DEFAULT_ENCODING = "latin-1"


# Try import PyPDF for PDF support
try:
    from pypdf import PdfReader
    PYPDF_AVAILABLE = True
except Exception:
    PYPDF_AVAILABLE = False

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def save_progress(state: dict):
    try:
        with open(PROGRESS_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f)
    except Exception:
        pass

def load_progress() -> dict:
    if PROGRESS_FILE.exists():
        try:
            with open(PROGRESS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_report(results: dict):
    try:
        with open(REPORT_FILE, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
    except Exception:
        pass


# HASH SUPPORT
def get_hash(text: str, algorithm: str) -> str:
    algorithm = algorithm.lower()
    data = text.encode("utf-8", errors="ignore")
    if algorithm == "md5":      return hashlib.md5(data).hexdigest()
    elif algorithm == "sha1":   return hashlib.sha1(data).hexdigest()
    elif algorithm == "sha224": return hashlib.sha224(data).hexdigest()
    elif algorithm == "sha256": return hashlib.sha256(data).hexdigest()
    elif algorithm == "sha512": return hashlib.sha512(data).hexdigest()
    raise ValueError("Unsupported hash algorithm: " + algorithm)

def check_bcrypt(password: str, stored_hash: str) -> bool:
    import bcrypt
    return bcrypt.checkpw(
        password.encode("utf-8"),
        stored_hash.encode("utf-8")
    )


# FILE PASSWORD TARGETS

def try_open_pdf_with_password(pdf_path, password):
    if not PYPDF_AVAILABLE:
        raise RuntimeError("PyPDF required. pip install pypdf")
    try:
        r = PdfReader(pdf_path)
    except Exception:
        return False
    try:
        return r.decrypt(password) != 0
    except Exception:
        return False

def try_open_zip_with_password(zip_path, password):
    try:
        with zipfile.ZipFile(zip_path) as zf:
            if not zf.namelist():
                return False
            try:
                zf.read(zf.namelist()[0], pwd=password.encode('utf-8'))
                return True
            except RuntimeError:
                return False
    except Exception:
        return False
def try_open_office_with_password(file_path, password):
    try:
        with open(file_path, 'rb') as f:
            office_file = msoffcrypto.OfficeFile(f)
            office_file.load_key(password=password)
            # Decrypt to memory/dummy to verify password correctness
            with open(os.devnull, 'wb') as dummy_out:
                office_file.decrypt(dummy_out)
            return True
    except Exception:
        return False

# Example for password-protected text files (basic check, may need custom)
def try_open_text_with_password(file_path, password):
    # Implement if you have encryption method for text files
    # Placeholder example: always return False as no standard encryption
    return False

def try_open_file_with_password(file_path, password):
    ext = os.path.splitext(file_path)[-1].lower()
    if ext in FILE_TESTERS:
        return FILE_TESTERS[ext](file_path, password)
    raise ValueError("Unhandled file type: " + ext)

FILE_TESTERS: Dict[str, Callable[[str, str], bool]] = {
    ".pdf": try_open_pdf_with_password,
    ".zip": try_open_zip_with_password,
    ".docx": try_open_office_with_password,
    ".xlsx": try_open_office_with_password,
    ".txt": try_open_text_with_password,
}

# MASK/HYBRID SUPPORT
DEFAULT_CHARSETS = {
    "l": string.ascii_lowercase,
    "u": string.ascii_uppercase,
    "d": string.digits,
    "s": SPECIAL_CHARS,
    "a": string.ascii_letters + string.digits + SPECIAL_CHARS,
}

def expand_hashcat_mask(maskstr: str) -> List[List[str]]:
    pools = []
    i = 0
    while i < len(maskstr):
        if maskstr[i] != "?":
            pools.append([maskstr[i]])
            i += 1
            continue
        token = maskstr[i+1]
        pools.append(list(DEFAULT_CHARSETS.get(token, [])))
        i += 2
    return pools

def hybrid_candidates(wordlist: List[str], mask: str) -> [str]:
    pools = expand_hashcat_mask(mask)
    for word in wordlist:
        for tail in itertools.product(*pools):
            yield word + "".join(tail)


# MANGLE RULE SUPPORT (partial)

def simple_mangle(word: str, rule: str) -> str:
    if rule == "$d":
        return word + "1"
    if rule == "r":
        return word[::-1]
    if rule == "c":
        return word.capitalize()
    if rule == "$s":
        return word + "!"
    return word

def apply_rules(word: str, rules: List[str]):
    yield word
    for rule in rules:
        yield simple_mangle(word, rule)


# ATTACK MODES

def is_file_path(target: str) -> bool:
    return os.path.isfile(target)

def batch_check_file_passwords(cands, file_path):
    for i, pwd in enumerate(cands, 1):
        if try_open_file_with_password(file_path, pwd):
            return pwd
        if i % PRINT_INTERVAL == 0:
            print(f"Attempts in batch: {i}, last tried: '{pwd}'")
    return None

def run_dictionary_attack(target, algorithm, wordlist_file, rules=[]):
    attempts, found = 0, None
    is_file = is_file_path(target)

    with open(wordlist_file, encoding=DEFAULT_ENCODING, errors="ignore") as f:
        for line_no, base_word in enumerate(f, 1):
            base = base_word.strip()
            tried = set()

            for candidate in apply_rules(base, rules):
                if candidate in tried:
                    continue
                tried.add(candidate)
                attempts += 1

                if is_file:
                    if try_open_file_with_password(target, candidate):
                        print(
                            f"Found password for file after {attempts:,} attempts "
                            f"(line {line_no}): '{candidate}'"
                        )
                        return candidate
                else:
                    if algorithm == "bcrypt":
                        if check_bcrypt(candidate, target):
                            print(
                                f"Found bcrypt password after {attempts:,} attempts "
                                f"(line {line_no}): '{candidate}'"
                            )
                            return candidate
                    else:
                        if get_hash(candidate, algorithm) == target:
                            print(
                                f"Found hash password after {attempts:,} attempts "
                                f"(line {line_no}): '{candidate}'"
                            )
                            return candidate

            if attempts % PRINT_INTERVAL == 0:
                print(f"Attempts: {attempts:,}, last tried: '{candidate}'")
                save_progress({
                    "mode": "dictionary",
                    "attempts": attempts,
                    "last": candidate,
                    "line": line_no
                })

            if attempts >= MAX_DICTIONARY_ATTEMPTS_SESSION:
                print("Dictionary cap reached. Stopping.")
                break
    return None


def batch_hashes(cands, target_hash, algorithm):
    for c in cands:
        if algorithm == "bcrypt":
            if check_bcrypt(c, target_hash):
                return c
        else:
            if get_hash(c, algorithm) == target_hash:
                return c
    return None

def batch_iter(iterable, size):
    batch = []
    for x in iterable:
        batch.append(x)
        if len(batch) == size:
            yield batch
            batch = []
    if batch:
        yield batch


def run_brute_force(target, algorithm, charset, min_len, max_len, batch_size=20000, mp_workers=1):
    found = None
    is_file = is_file_path(target)

    # Calculate total search space size (approx)
    total_size = 0
    for length in range(min_len, max_len + 1):
        total_size += len(charset) ** length

    attempts = 0
    start_time = time.time()

    if mp_workers > 1:
        with ProcessPoolExecutor(max_workers=mp_workers) as p:
            futures = []
            batch_count = 0
            for length in range(min_len, max_len + 1):
                it = itertools.product(charset, repeat=length)
                for batch in batch_iter(it, batch_size):
                    batch_count += 1
                    batch_str = [''.join(tup) for tup in batch]
                    print(f"Trying batch #{batch_count}, length {length}, {len(batch_str)} candidates...")
                    if is_file:
                        futures.append(p.submit(batch_check_file_passwords, batch_str, target))
                    else:
                        futures.append(p.submit(batch_hashes, batch_str, target, algorithm))
            for fut in as_completed(futures):
                try:
                    result = fut.result()
                except Exception as e:
                    eprint("Worker exception:", e)
                    continue
                if result:
                    found = result
                    # Cancel all remaining futures
                    for f in futures:
                        f.cancel()
                    break
                attempts += batch_size
                elapsed = time.time() - start_time
                est_total = (elapsed / attempts) * total_size if attempts else 0
                est_remain = est_total - elapsed
                if attempts % (PRINT_INTERVAL*10) == 0:
                    print(f"Attempts: {attempts:,} / {total_size:,}, elapsed: {elapsed:.1f}s, est. remaining: {est_remain:.1f}s")
    else:
        batch_count = 0
        for length in range(min_len, max_len + 1):
            it = itertools.product(charset, repeat=length)
            for batch in batch_iter(it, batch_size):
                batch_count += 1
                batch_str = [''.join(tup) for tup in batch]
                print(f"Trying batch #{batch_count}, length {length}, {len(batch_str)} candidates...")
                if is_file:
                    result = batch_check_file_passwords(batch_str, target)
                else:
                    result = batch_hashes(batch_str, target, algorithm)
                attempts += len(batch_str)
                elapsed = time.time() - start_time
                est_total = (elapsed / attempts) * total_size if attempts else 0
                est_remain = est_total - elapsed
                if attempts % (PRINT_INTERVAL*10) == 0 or result:
                    print(f"Attempts: {attempts:,} / {total_size:,}, elapsed: {elapsed:.1f}s, est. remaining: {est_remain:.1f}s")
                if result:
                    found = result
                    break
            if found:
                break

    return found


def run_mask_attack(target, algorithm, mask, wordlist_file=None):
    is_file = is_file_path(target)
    if wordlist_file:
        wl = [x.strip() for x in open(wordlist_file, encoding=DEFAULT_ENCODING, errors='ignore')]
        candidates = hybrid_candidates(wl, mask)
    else:
        pools = expand_hashcat_mask(mask)
        candidates = (''.join(x) for x in itertools.product(*pools))

    attempts = 0
    start_time = time.time()
    for candidate in candidates:
        attempts += 1
        if is_file:
            if try_open_file_with_password(target, candidate):
                print(f"Found password for file after {attempts:,} attempts: '{candidate}'")
                return candidate
        else:
            if algorithm == "bcrypt":
                if check_bcrypt(candidate, target):
                    return candidate
            else:
                if get_hash(candidate, algorithm) == target:
                    return candidate
        if attempts % PRINT_INTERVAL == 0:
            elapsed = time.time() - start_time
            print(f"Attempts: {attempts:,}, elapsed: {elapsed:.1f} seconds, last tried: '{candidate}'")
            save_progress({"mode": "mask", "attempts": attempts, "last": candidate, "mask": mask})
        if attempts >= MAX_BRUTE_COMBINATIONS:
            print("Mask brute cap reached.")
            break
    return None


# CLI + ORCHESTRATION + SAFETY

def show_charset_rules_brute():
    print("""
Brute Force Charset Rules:
  Specify character sets included anywhere in password:
    ?l - lowercase letters (a-z)
    ?u - uppercase letters (A-Z)
    ?d - digits (0-9)
    ?s - special characters (!@#$%^&*()-_+=[]{};:,.<>/?\\|`~)
    ?a - all letters + digits + specials
Example: ?u?l?d  (password contains uppercase, lowercase, and digits in any order)
""")

def show_mask_rules():
    print("""
Mask Attack Rules:
  Specify exact character type per position (exact password length):
    ?l - lowercase letter
    ?u - uppercase letter
    ?d - digit
    ?s - special character (!@#$%^&*()-_+=[]{};:,.<>/?\\|`~)
    Literal characters allowed (try 'x', '1', etc.)
    Example: ?u?l?l?l?d  
  [1 uppercase letter, next 3 lowercase letters, then 1 digit]
""")

def show_hybrid_rules():
    print("""
Hybrid Attack Rules:
  Starts with dictionary words and appends mask-based suffix
Mask tokens same as mask attack rules apply for suffix/prefix:
Example:
  Base word: password
  Mask suffix: ?d?d
Generates:
  password00, password01, ..., password99
""")


def interactive():
    print("== Password Audit & Recovery Tool ==")
# Command line args: 1st arg can be target (hash or PDF path)
    target_arg = sys.argv[1] if len(sys.argv) > 1 else None
    target_type = None
    target = None
    algorithm = None

    if target_arg:
        # Decide if file or hash based on whether file exists
        if os.path.isfile(target_arg):
            target = target_arg
            target_type = "2"  # PDF File
            algorithm = "sha256"
            print(f"Using PDF file from argument: {target}")
        else:
            target = target_arg
            target_type = "1"  # Hash string
            algorithm = input("Hash algorithm [md5, sha1, sha224, sha256, sha 512,]: ").strip().lower() or "sha256"
            print(f"Using hash from argument: {target}")
    else:
        # No argument: ask user
        print("\nSelect target type:")
        print("1. Hash string")
        print("2. PDF file")
        target_type = input("Enter target type number: ").strip()
        if target_type == "1":
            target = input("Enter hash string: ").strip()
            algorithm = input("Hash algorithm [md5, sha1, sha224, sha256, sha 512]: ").strip().lower() or "sha256"
        elif target_type == "2":
            if not PYPDF_AVAILABLE:
                print("PyPDF is required for PDF cracking. Install with: pip install pypdf")
                return
            target = input("Enter full path to Password Protected File: ").strip()
            if not os.path.isfile(target):
                print("File not found, aborting.")
                return
            algorithm = "sha256"
        else:
            print("Unknown target type, aborting.")
            return

    print("\nSelect attack mode:")
    print("1. Dictionary Attack")
    print("2. Mask Attack")
    print("3. Hybrid Attack")
    print("4. Brute Force Attack")
    mode = input("Enter mode number: ").strip()

    found = None

    if mode == "1":
        # Dictionary attack
        wlf = input("Enter full path to wordlist file: ").strip()

        if not os.path.isfile(wlf):
            print("Wordlist file not found or inaccessible. Aborting.")
            return
        print("""Available dictionary attack rules:
$d  - append "1" digit
r   - reverse the word
c   - capitalize the word
$s  - append "!" special character
Press enter to apply no rules""")

        rules_input = input("Enter your choice: ").strip()
        rules = rules_input.split(",") if rules_input else []
        found = run_dictionary_attack(target, algorithm, wlf, rules)


    elif mode == "2":
        show_mask_rules()
        mask = input("Enter mask (e.g. ?u?l?l?l?d): ").strip()
        wlf = input("Wordlist file (leave empty if not hybrid): ").strip() or None
        found = run_mask_attack(target, algorithm, mask, wordlist_file=wlf)


    elif mode == "3":
        show_hybrid_rules()
        mask = input("Enter mask (e.g. ?u?l?l?l?d): ").strip()
        wlf = input("Wordlist file (required): ").strip()
        if not os.path.isfile(wlf):
            print("Wordlist file not found or inaccessible. Aborting.")
            return
        found = run_mask_attack(target, algorithm, mask, wordlist_file=wlf)

    elif mode == "4":
        show_charset_rules_brute()
        charset = input("Charset (?l?u?d?s or literal): ").strip()
        expanded_charset = ""
        if charset.startswith("?"):
            for t in re.findall(r"\?([luds])", charset):
                expanded_charset += DEFAULT_CHARSETS.get(t, "")
        else:
            expanded_charset = charset
        try:
            min_len = int(input("Min length: ").strip())
            max_len = int(input("Max length: ").strip())
        except Exception:
            min_len, max_len = 1, 6
        mp_workers = int(input("Multiprocessing (1 = no MP): ").strip() or "1")
        found = run_brute_force(target, algorithm, expanded_charset, min_len, max_len, mp_workers=mp_workers)
    else:
        print("Unknown mode selected. Aborting.")
        return
    if found:
        print("\nCrack successful! Password found:")
        print(found)
    else:
        print("\nPassword NOT found within given parameters.")

if __name__ == "__main__":
    interactive()

