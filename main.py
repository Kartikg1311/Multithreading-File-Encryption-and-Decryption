import os
import time
import logging
import threading
import platform
import resource
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
import base64
import getpass

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn

console = Console()

# Setup logging
logging.basicConfig(filename='encryption_log.txt', level=logging.INFO,
                    format='%(asctime)s - %(threadName)s - %(message)s')

# Cross-platform resource usage getter
def get_usage():
    if platform.system() == "Darwin":
        return resource.getrusage(resource.RUSAGE_SELF)
    else:
        return resource.getrusage(resource.RUSAGE_THREAD)

# Basic password-based key derivation (no salt)
def derive_key(password: str) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(password.encode())
    return base64.urlsafe_b64encode(digest.finalize())

def has_access(filename: str) -> (bool, str):
    can_read = os.access(filename, os.R_OK)
    can_write = os.access(filename, os.W_OK)
    if not can_read and not can_write:
        return False, "No read or write permission"
    if not can_read:
        return False, "No read permission"
    if not can_write:
        return False, "No write permission"
    return True, "Read/Write permissions OK"

def encrypt_file(filename: str, key: bytes, progress_task_id, progress):
    thread_name = threading.current_thread().name
    has_perm, perm_msg = has_access(filename)
    if not has_perm:
        logging.error(f"{thread_name} - Encrypt - {filename} - Failed: {perm_msg}")
        console.print(f"[red][{thread_name}] Permission error on {filename}: {perm_msg}[/red]")
        progress.update(progress_task_id, advance=1)
        return

    try:
        usage_start = get_usage()
        start_time = time.time()

        fernet = Fernet(key)
        with open(filename, "rb") as f:
            data = f.read()

        chunk_size = max(len(data) // 10, 1)
        encrypted_chunks = []
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i+chunk_size]
            encrypted_chunks.append(fernet.encrypt(chunk))
            time.sleep(0.05)
            progress.update(progress_task_id, advance=1)

        encrypted = b"".join(encrypted_chunks)
        with open(filename, "wb") as f:
            f.write(encrypted)

        end_time = time.time()
        usage_end = get_usage()

        cpu_time = (usage_end.ru_utime - usage_start.ru_utime) + (usage_end.ru_stime - usage_start.ru_stime)
        duration = end_time - start_time

        logging.info(f"{thread_name} - Encrypt - {filename} - Success - Duration: {duration:.2f}s - CPU time: {cpu_time:.2f}s")
        console.print(f"[green][{thread_name}] Encrypted {filename} successfully in {duration:.2f}s (CPU {cpu_time:.2f}s)[/green]")

    except Exception as e:
        logging.error(f"{thread_name} - Encrypt - {filename} - Failed: {e}")
        console.print(f"[red][{thread_name}] Encryption failed for {filename}: {e}[/red]")
        progress.update(progress_task_id, advance=1)

def decrypt_file(filename: str, key: bytes, progress_task_id, progress):
    thread_name = threading.current_thread().name
    has_perm, perm_msg = has_access(filename)
    if not has_perm:
        logging.error(f"{thread_name} - Decrypt - {filename} - Failed: {perm_msg}")
        console.print(f"[red][{thread_name}] Permission error on {filename}: {perm_msg}[/red]")
        progress.update(progress_task_id, advance=1)
        return

    try:
        usage_start = get_usage()
        start_time = time.time()

        fernet = Fernet(key)
        with open(filename, "rb") as f:
            encrypted_data = f.read()

        chunk_size = max(len(encrypted_data) // 10, 1)
        decrypted_chunks = []
        for i in range(0, len(encrypted_data), chunk_size):
            chunk = encrypted_data[i:i+chunk_size]
            decrypted_chunks.append(fernet.decrypt(chunk))
            time.sleep(0.05)
            progress.update(progress_task_id, advance=1)

        decrypted = b"".join(decrypted_chunks)
        with open(filename, "wb") as f:
            f.write(decrypted)

        end_time = time.time()
        usage_end = get_usage()

        cpu_time = (usage_end.ru_utime - usage_start.ru_utime) + (usage_end.ru_stime - usage_start.ru_stime)
        duration = end_time - start_time

        logging.info(f"{thread_name} - Decrypt - {filename} - Success - Duration: {duration:.2f}s - CPU time: {cpu_time:.2f}s")
        console.print(f"[green][{thread_name}] Decrypted {filename} successfully in {duration:.2f}s (CPU {cpu_time:.2f}s)[/green]")

    except InvalidToken:
        logging.error(f"{thread_name} - Decrypt - {filename} - Failed: Invalid key/token")
        console.print(f"[red][{thread_name}] Decryption failed for {filename}: Invalid key or corrupted file[/red]")
        progress.update(progress_task_id, advance=1)
    except Exception as e:
        logging.error(f"{thread_name} - Decrypt - {filename} - Failed: {e}")
        console.print(f"[red][{thread_name}] Decryption failed for {filename}: {e}[/red]")
        progress.update(progress_task_id, advance=1)

def worker(files, key, operation, progress):
    thread_name = threading.current_thread().name
    for filename in files:
        task_id = progress.add_task(f"[cyan]{thread_name} processing {filename}", total=10)
        if operation == 'encrypt':
            encrypt_file(filename, key, task_id, progress)
        elif operation == 'decrypt':
            decrypt_file(filename, key, task_id, progress)
        else:
            progress.update(task_id, advance=10)

def main():
    console.print("[bold yellow]Choose operation:[/bold yellow]\n  E - Encrypt\n  D - Decrypt\n  Q - Quit")
    choice = input("Enter your choice: ").strip().lower()

    if choice not in ['e', 'd']:
        console.print("[red]Quitting program.[/red]")
        return

    password = getpass.getpass("Enter your password: ")
    key = derive_key(password)

    filenames_input = input("Enter file names separated by spaces: ").strip()
    if not filenames_input:
        console.print("[red]No files provided. Exiting.[/red]")
        return

    files = filenames_input.split()
    missing = [f for f in files if not os.path.isfile(f)]
    if missing:
        console.print(f"[red]Missing files: {', '.join(missing)}[/red]")
        return

    console.print("\n[bold yellow]Choose scheduling policy:[/bold yellow]\n  1 - FCFS (First Come First Serve)\n  2 - Default (Parallel Threads)")
    sched_choice = input("Enter scheduling choice [1/2]: ").strip()
    is_fcfs = sched_choice == '1'

    thread_count = min(4, len(files))
    chunk_size = (len(files) + thread_count - 1) // thread_count
    files_per_thread = {f"Thread-{i+1}": files[i*chunk_size:(i+1)*chunk_size] for i in range(thread_count)}

    table = Table(title="Scheduler - File Assignment to Threads")
    table.add_column("Thread", justify="center")
    table.add_column("Files Assigned")
    for thread, assigned_files in files_per_thread.items():
        table.add_row(thread, ", ".join(assigned_files) if assigned_files else "-")
    console.print(table)

    with Progress(
        "[progress.description]{task.description}",
        BarColumn(),
        "[progress.percentage]{task.percentage:>3.0f}%",
        TimeElapsedColumn(),
        console=console
    ) as progress:
        threads = []
        operation = 'encrypt' if choice == 'e' else 'decrypt'

        if is_fcfs:
            for i, filename in enumerate(files):
                thread_name = f"FCFS-Thread-{i+1}"
                task_id = progress.add_task(f"[cyan]{thread_name} processing {filename}", total=10)
                t = threading.Thread(target=lambda: encrypt_file(filename, key, task_id, progress) if operation == 'encrypt' else decrypt_file(filename, key, task_id, progress), name=thread_name)
                t.start()
                t.join()
        else:
            for i in range(thread_count):
                chunk = files_per_thread[f"Thread-{i+1}"]
                if not chunk:
                    continue
                t = threading.Thread(target=worker, args=(chunk, key, operation, progress), name=f"Thread-{i+1}")
                threads.append(t)
                t.start()
            for t in threads:
                t.join()

    console.print("[bold green]All operations completed.[/bold green]")

if __name__ == "__main__":
    main()