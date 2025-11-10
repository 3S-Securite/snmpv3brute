#!/usr/bin/env python3
"""
snmpv3brute (refactor)
Refactored from original by Scott Thomas.

Usage: cf. --help
"""
from __future__ import annotations
import argparse
import hashlib
import sys
import time
from dataclasses import dataclass
from multiprocessing import Pool
from typing import List, Optional, Tuple
from binascii import unhexlify
import os
import logging

try:
    import pyshark
except Exception:
    pyshark = None

# ---------- Constants ----------
L_REPEAT = 1_048_576  # same as original 'l'
IPAD_BYTES = bytes.fromhex("36" * 64)
OPAD_BYTES = bytes.fromhex("5c" * 64)

# ---------- Colors (kept for CLI UX) ----------
class Color:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'


# ---------- Data structures ----------
@dataclass
class Task:
    id: int
    ip_src: str
    ip_dst: str
    username: str
    engine_id_hex: str
    auth_params_hex: str
    whole_msg_hex: str


@dataclass
class WorkerContext:
    engine_id: bytes
    auth_params: str  # hex string (24 chars expected)
    whole_msg_mod: bytes
    algorithms: List[str]  # ['md5','sha'] etc


# Global context variable to be set in worker processes
WORKER_CTX: Optional[WorkerContext] = None


# ---------- Utility functions ----------
def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format='[%(levelname)s] %(message)s')


def read_wordlist_lines(path: str):
    with open(path, 'r', encoding='latin-1') as fh:
        for line in fh:
            yield line.rstrip('\n\r')


# ---------- PCAP parsing ----------
def extract_tasks_from_pcap(pcap_path: str, manual_snmp: Optional[List[str]] = None, verbose: bool = False) -> List[Task]:
    """
    Extract SNMPv3 relevant fields from a PCAP file using pyshark.
    If manual_snmp is provided (3 elements), include it as a Task.
    """
    tasks: List[Task] = []
    counter = 1

    if manual_snmp:
        engine, auth_params, whole = manual_snmp
        tasks.append(Task(counter, "manual", "manual", "manual", engine, auth_params, whole))
        counter += 1

    if not pcap_path:
        return tasks

    if pyshark is None:
        raise RuntimeError("pyshark is required for PCAP parsing but is not available in this environment.")

    logging.info("Processing pcap %s for SNMPv3 packets...", pcap_path)
    cap = pyshark.FileCapture(
        pcap_path,
        display_filter='udp.srcport==161&&snmp.msgVersion==3&&snmp.msgUserName!=""',
        include_raw=True,
        use_json=True
    )

    seen = set()
    try:
        for pkt in cap:
            try:
                if int(pkt.udp.srcport) != 161 or int(pkt.snmp.msgVersion) != 3:
                    continue

                # Unique key to avoid duplicates: (ip.src, ip.dst, username)
                key = (pkt.ip.src, pkt.ip.dst, pkt.snmp.msgUserName)
                if key in seen:
                    continue
                seen.add(key)

                engine_hex = pkt.snmp.msgAuthoritativeEngineID_raw[0]
                auth_hex = pkt.snmp.msgAuthenticationParameters_raw[0]
                whole_hex = pkt.snmp_raw.value  # raw SNMP whole message

                tasks.append(Task(counter, pkt.ip.src, pkt.ip.dst, pkt.snmp.msgUserName,
                                  engine_hex, auth_hex, whole_hex))
                counter += 1
            except AttributeError:
                if verbose:
                    logging.debug("Packet %s missing some attributes; skipping.", getattr(pkt, 'frame_info', {}).get('number', '?'))
            except Exception as e:
                if verbose:
                    logging.debug("Error processing packet: %s", e)
    finally:
        cap.close()

    return tasks


# ---------- Auth calculation ----------
def _pad_authkey_to_64(authkey_hex: str) -> bytes:
    """
    Convert auth key hex (e.g. md5 hex) to 64-byte key by padding with zeros (as bytes).
    """
    raw = bytes.fromhex(authkey_hex)
    if len(raw) > 64:
        return raw[:64]
    return raw + b'\x00' * (64 - len(raw))


def _compute_auth_test(passphrase: str, context: WorkerContext, algo: str) -> bool:
    """
    Compute the SNMPv3 msgAuthenticationParameters (truncated) for given passphrase and compare.
    Returns True if matches.
    """
    passphrase = passphrase.rstrip()
    if not passphrase:
        return False

    # build repeated data (latin-1 encoding like original)
    data = (passphrase * (L_REPEAT // len(passphrase) + 1))[:L_REPEAT].encode('latin-1')

    if algo == 'md5':
        digest1 = hashlib.md5(data).digest()
        authkey_hex = hashlib.md5(digest1 + context.engine_id + digest1).hexdigest()
        digest_fn = hashlib.md5
    elif algo == 'sha':
        digest1 = hashlib.sha1(data).digest()
        authkey_hex = hashlib.sha1(digest1 + context.engine_id + digest1).hexdigest()
        digest_fn = hashlib.sha1
    else:
        raise ValueError("Unsupported algorithm: " + algo)

    # extend authkey to 64 bytes (as bytes)
    extended = _pad_authkey_to_64(authkey_hex)

    # K1 = extended ^ ipad, K2 = extended ^ opad
    K1 = bytes(a ^ b for a, b in zip(extended, IPAD_BYTES))
    K2 = bytes(a ^ b for a, b in zip(extended, OPAD_BYTES))

    # Hash chain
    h1 = digest_fn(K1 + context.whole_msg_mod).digest()
    h2 = digest_fn(K2 + h1).hexdigest()

    # Compare first 24 hex chars (as original implementation)
    if h2[:24].lower() == context.auth_params.lower():
        return True
    return False


# Worker initializer for Pool
def _init_worker(ctx: WorkerContext):
    global WORKER_CTX
    WORKER_CTX = ctx


# Worker function — called in worker processes (must be at module top-level)
def _worker_check_line(line: str) -> Optional[Tuple[str, str]]:
    """
    line is a password candidate (already stripped of newline)
    Returns (password, alg_name) on success, else None.
    """
    global WORKER_CTX
    if WORKER_CTX is None:
        raise RuntimeError("Worker context not initialized")

    candidate = line.rstrip()
    if not candidate:
        return None

    for algo in WORKER_CTX.algorithms:
        try:
            if _compute_auth_test(candidate, WORKER_CTX, algo):
                return (candidate, algo.upper())
        except Exception:
            # swallow per-candidate exceptions so pool doesn't crash
            logging.debug("Exception testing candidate '%s' with %s", candidate, algo, exc_info=True)
            continue
    return None


# ---------- CLI / Main flow ----------
def print_banner():
    banner = r"""
                                ____  _                _       
                               |___ \| |              | |      
  ___ _ __  _ __ ___  _ ____   ____) | |__  _ __ _   _| |_ ___ 
 / __| '_ \| '_ ` _ \| '_ \ \ / /__ <| '_ \| '__| | | | __/ _ \
 \__ \ | | | | | | | | |_) \ V /___) | |_) | |  | |_| | ||  __/
 |___/_| |_|_| |_| |_| .__/ \_/|____/|_.__/|_|   \__,_|\__\___|
                     | |        refactor by Antoine PERRIN            
                     |_|         assisted by Kévin LE CROLLER
"""
    print(banner)


def format_task_row(t: Task, id_width: int, ip_width: int, user_width: int) -> str:
    return f" {str(t.id).zfill(2):>{id_width}}  {t.ip_src:<{ip_width}}  {t.username:<{user_width}}"


def main():
    parser = argparse.ArgumentParser(description="SNMPv3 auth bruteforce (refactor)")
    parser.add_argument("-a", "--algo", nargs='?', choices=['md5', 'sha', 'all'],
                        default='all', help="Hash algorithm to try (default: all)")
    parser.add_argument("-w", "--wordlist", help="Wordlist file (one password per line)")
    parser.add_argument("-W", "--words", help="One or more words (space separated)", nargs='*', default=[])
    parser.add_argument("-p", "--pcap", help="PCAP/PCAPNG file to parse for SNMPv3 packets")
    parser.add_argument("-m", "--manual", nargs=3, metavar=('engine_id','auth_params','whole_msg'),
                        help="Provide manually engineID authParams wholeMsg (hex strings)")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    setup_logging(args.verbose)
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    if not args.wordlist and not args.words:
        logging.error("You must provide a -w wordlist or -W single word(s).")
        sys.exit(1)

    if not args.pcap and not args.manual:
        logging.error("You must provide a -p pcap file or -m manual SNMP variables.")
        sys.exit(1)

    if args.pcap and args.manual:
        logging.error("Please specify either -p (pcap) OR -m (manual), not both.")
        sys.exit(1)

    if args.pcap and not os.path.exists(args.pcap):
        logging.error("PCAP file %s does not exist.", args.pcap)
        sys.exit(1)

    if args.wordlist and not os.path.exists(args.wordlist):
        logging.error("Wordlist %s does not exist.", args.wordlist)
        sys.exit(1)

    # banner
    print_banner()

    # Build hash algorithm list
    if args.algo == 'all':
        algos = ['md5', 'sha']
    else:
        algos = [args.algo]

    # Extract tasks
    tasks = extract_tasks_from_pcap(args.pcap, args.manual, verbose=args.verbose)
    if not tasks:
        logging.error("No tasks found (no SNMPv3 packets extracted and no manual entry). Exiting.")
        sys.exit(1)

    # Pretty columns width
    id_w = 2
    ip_w = max(10, max(len(t.ip_src) for t in tasks))
    user_w = max(8, max(len(t.username) for t in tasks))

    # Print tasks
    print(Color.BOLD + "\nTasks to be processed:" + Color.END)
    print(f" ID  {'IP address':<{ip_w}}  {'Username':<{user_w}}")
    print("-" * (5 + ip_w + user_w))
    for t in tasks:
        print(format_task_row(t, id_w, ip_w, user_w))

    print(Color.BOLD + "\nResults:" + Color.END)
    print(f" ID  {'IP address':<{ip_w}}  {'Username':<{user_w}}  {'Alg':<5}  Password")
    print("-" * (5 + ip_w + user_w + 20))

    # For each task, build a WorkerContext and test words
    for t in tasks:
        keep_trying = True
        password_found: Optional[Tuple[str, str]] = None

        # Prepare per-task context
        try:
            engine_bytes = unhexlify(t.engine_id_hex)
            auth_params = t.auth_params_hex.lower()
            # whole_msg_mod: replace auth field with zeros (24 hex chars)
            whole_mod_hex = t.whole_msg_hex.replace(t.auth_params_hex, '0' * 24)
            whole_mod_bytes = unhexlify(whole_mod_hex)
        except Exception as e:
            logging.error("Failed to parse hex fields for task %d: %s", t.id, e)
            continue

        ctx = WorkerContext(engine_id=engine_bytes, auth_params=auth_params, whole_msg_mod=whole_mod_bytes, algorithms=algos)

        # Print task header (inline)
        start_time = time.time()
        prefix = f" {str(t.id).zfill(2)}  {t.ip_src:<{ip_w}}  {t.username:<{user_w}}"
        print(prefix + " " + Color.YELLOW + f"{' / '.join(a.upper() for a in algos)}   Trying..." + Color.END, end='\r')

        # First test the explicit provided words (quick synchronous checks)
        if args.words and keep_trying:
            for w in args.words:
                if _compute_auth_test(w, ctx, 'md5') if 'md5' in ctx.algorithms and 'sha' not in ctx.algorithms else False:
                    # this branch earlier logic (legacy) - better to call per algorithm
                    pass
                # call properly for each algorithm
                for algo in ctx.algorithms:
                    if _compute_auth_test(w, ctx, algo):
                        password_found = (w, algo.upper())
                        keep_trying = False
                        break
                if not keep_trying:
                    break

        # If not found, and there is a wordlist, use Pool
        if args.wordlist and keep_trying:
            # Initialize pool workers with context
            p = Pool(initializer=_init_worker, initargs=(ctx,))
            try:
                # streaming over the wordlist lines
                for result in p.imap_unordered(_worker_check_line, read_wordlist_lines(args.wordlist), chunksize=1000):
                    if result:
                        password_found = result
                        keep_trying = False
                        p.terminate()
                        break
            finally:
                p.close()
                p.join()

        end_time = time.time()
        elapsed = end_time - start_time

        if password_found:
            print(prefix + " " + Color.GREEN + f"{password_found[1]:<5}   {password_found[0]}" + Color.END + f" ({elapsed:.2f}s)")
        else:
            print(prefix + " " + Color.RED + "N/A    Not found" + Color.END + f" ({elapsed:.2f}s)")

    print("")


if __name__ == "__main__":
    main()
