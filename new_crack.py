import zipfile
import rarfile
import itertools
import string
import time
import tkinter as tk
from tkinter import filedialog
from tkinter import ttk
from tkinter import font
from tkinter import messagebox
from multiprocessing import Pool, Manager, set_start_method

def crack_password_chunk(file_path, max_length, chars, file_type, start_idx, chunk_size, progress_dict):
    """Brute-force attack to crack ZIP or RAR password in chunks with parallel processing."""
    if file_type == "ZIP":
        archive = zipfile.ZipFile(file_path)
        extract_func = lambda pwd: archive.extractall(pwd=pwd.encode())
    elif file_type == "RAR":
        archive = rarfile.RarFile(file_path)
        extract_func = lambda pwd: archive.extractall(pwd=pwd)
    else:
        return None

    combinations = itertools.product(chars, repeat=max_length)
    chunk = list(itertools.islice(combinations, start_idx, start_idx + chunk_size))

    for guess in chunk:
        guess = ''.join(guess)
        try:
            progress_dict["status"] = f"Trying password: {guess}"
            progress_dict["progress"] += 1
            extract_func(guess)
            return guess
        except Exception:
            continue

    return None

def crack_password(file_path, max_length, chars, file_type, progress_dict, status_label, progress_bar, unknown_length):
    """Wrapper function to divide the password cracking process into chunks for parallel processing."""
    total_combinations = len(chars) ** max_length
    progress_bar['maximum'] = total_combinations
    num_processes = 4  # Adjust this based on the number of CPU cores

    chunk_size = total_combinations // num_processes
    tasks = []

    with Manager() as manager:
        progress_dict["status"] = "Starting password crack..."
        progress_dict["progress"] = 0

        with Pool(processes=num_processes) as pool:
            for i in range(num_processes):
                start_idx = i * chunk_size
                tasks.append(pool.apply_async(crack_password_chunk, (file_path, max_length, chars, file_type, start_idx, chunk_size, progress_dict)))

            while True:
                running = any(not task.ready() for task in tasks)
                if not running:
                    break

                status_label.config(text=progress_dict["status"])
                progress_bar['value'] = progress_dict["progress"]
                status_label.update()
                progress_bar.update()
                time.sleep(0.1)

            for task in tasks:
                result = task.get()
                if result:
                    return result

    return None

def log_result(file_path, password, duration):
    """Logs the found password into a file."""
    with open("crack_log.txt", "a") as log_file:
        log_file.write(f"File: {file_path}, Password: {password}, Time: {duration:.2f} sec\n")

def start_cracking():
    """Starts the password cracking process from the GUI."""
    file_path = filedialog.askopenfilename()
    if not file_path:
        return
    
    file_type = "ZIP" if file_path.endswith(".zip") else "RAR"
    max_length = int(max_length_var.get()) if not unknown_length_var.get() else None
    chars = string.ascii_lowercase + string.digits if use_default_chars.get() else custom_chars_var.get()
    
    status_label.config(text="Cracking in Progress...")
    password_label.config(text="Password: Not Found")
    
    # Create a Manager to store the status and progress
    with Manager() as manager:
        progress_dict = manager.dict()

        if unknown_length_var.get():
            # If the password length is unknown, try incremental lengths from 1 to 12
            max_length = 1
            result = None
            while max_length <= 12 and not result:  # Limit to max 12 characters for performance
                result = crack_password(file_path, max_length, chars, file_type, progress_dict, status_label, progress_bar, unknown_length=True)
                max_length += 1
        else:
            result = crack_password(file_path, max_length, chars, file_type, progress_dict, status_label, progress_bar, unknown_length=False)

    if result:
        password_label.config(text=f"Password: {result}")
        messagebox.showinfo("Password Found", f"Password: {result}")
    else:
        password_label.config(text="Password: Not Found")
        messagebox.showerror("Failed", "Password not found.")
    
    status_label.config(text="Process Completed")

if __name__ == "__main__":
    # Set the start method for multiprocessing to avoid spawning new Tkinter root windows
    set_start_method('spawn')

    # GUI Setup
    root = tk.Tk()
    root.title("ZIP & RAR Password Cracker")
    root.geometry("600x400")  # Set the window size
    root.configure(bg="#f4f4f9")

    # Define custom fonts
    title_font = font.Font(family="Helvetica", size=16, weight="bold")
    label_font = font.Font(family="Helvetica", size=12)
    status_font = font.Font(family="Helvetica", size=12, slant="italic")
    
    # Variables
    max_length_var = tk.StringVar(value="4")
    custom_chars_var = tk.StringVar(value=string.ascii_lowercase + string.digits)
    use_default_chars = tk.BooleanVar(value=True)
    unknown_length_var = tk.BooleanVar(value=False)

    # Title label
    title_label = tk.Label(root, text="ZIP & RAR Password Cracker", font=title_font, bg="#f4f4f9")
    title_label.pack(pady=10)

    # Max Password Length Input
    tk.Label(root, text="Max Password Length:", font=label_font, bg="#f4f4f9").pack(pady=5)
    tk.Entry(root, textvariable=max_length_var, font=label_font).pack(pady=5)

    # Default Chars Checkbox
    tk.Checkbutton(root, text="Use Default Chars (a-z, 0-9)", variable=use_default_chars, font=label_font, bg="#f4f4f9").pack(pady=5)

    # Custom Chars Input
    tk.Label(root, text="Custom Chars (if unchecked):", font=label_font, bg="#f4f4f9").pack(pady=5)
    tk.Entry(root, textvariable=custom_chars_var, font=label_font).pack(pady=5)

    # Unknown Length Checkbox
    tk.Checkbutton(root, text="Unknown Password Length", variable=unknown_length_var, font=label_font, bg="#f4f4f9").pack(pady=5)

    # Cracking Button
    tk.Button(root, text="Select File & Crack", font=label_font, bg="#4CAF50", fg="white", command=start_cracking).pack(pady=10)

    # Status Label
    status_label = tk.Label(root, text="Status: Waiting...", font=status_font, fg="blue", bg="#f4f4f9")
    status_label.pack(pady=5)

    # Progress Bar
    progress_bar = ttk.Progressbar(root, length=400, mode="determinate")
    progress_bar.pack(pady=10)

    # Password Display
    password_label = tk.Label(root, text="Password: Not Found", font=label_font, fg="red", bg="#f4f4f9")
    password_label.pack(pady=10)

    # Start the GUI main loop
    root.mainloop()
