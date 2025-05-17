import socket
import threading
import queue
import time
import logging
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from typing import Tuple, List
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import ttkbootstrap as ttkb
from ttkbootstrap.constants import *
import pandas as pd
from tqdm import tqdm
import colorlog

# Configure colorized logging with file output
def setup_logging():
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)  # Capture all logs for debugging

    # Console handler with color
    console_handler = colorlog.StreamHandler()
    console_handler.setFormatter(colorlog.ColoredFormatter(
        '%(log_color)s%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red,bg_white',
        }
    ))
    logger.addHandler(console_handler)

    # File handler for debugging
    file_handler = logging.FileHandler('port_scanner.log', mode='w')
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    logger.addHandler(file_handler)
    return logger

# Validate IP address
def is_valid_ip(ip: str) -> bool:
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

# Validate port range
def is_valid_port_range(start: int, end: int) -> bool:
    return 1 <= start <= end <= 65535

# Scan a single port
def scan_port(ip: str, port: int, timeout: float = 1.0) -> Tuple[int, bool, str]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return port, result == 0, ""
    except socket.gaierror:
        return port, False, "Invalid IP address or hostname"
    except socket.error as e:
        return port, False, f"Socket error: {str(e)}"
    except Exception as e:
        return port, False, f"Unexpected error: {str(e)}"

# Worker function for thread pool
def worker(ip: str, port_queue: queue.Queue, results: List[Tuple[int, bool, str]], 
           lock: threading.Lock, logger: logging.Logger, progress: tqdm):
    while not port_queue.empty():
        try:
            port = port_queue.get_nowait()
            logger.debug(f"Scanning port {port}")
            port, is_open, error = scan_port(ip, port)
            with lock:
                results.append((port, is_open, error))
                progress.update(1)
            if is_open:
                logger.info(f"Port {port} is OPEN")
            elif error:
                logger.error(f"Port {port}: {error}")
            port_queue.task_done()
        except queue.Empty:
            break
        except Exception as e:
            logger.error(f"Worker error on port {port}: {str(e)}")
            with lock:
                progress.update(1)
            port_queue.task_done()

# Main port scanning function
def scan_ports(ip: str, start_port: int, end_port: int, max_threads: int, 
               update_callback, complete_callback, logger):
    logger.info(f"Starting port scan on {ip} from port {start_port} to {end_port}")

    # Validate inputs
    if not is_valid_ip(ip):
        logger.error("Invalid IP address provided")
        complete_callback("Invalid IP address provided")
        return
    if not is_valid_port_range(start_port, end_port):
        logger.error("Invalid port range provided")
        complete_callback("Invalid port range provided")
        return

    # Initialize queue and results
    port_queue = queue.Queue()
    results = []
    lock = threading.Lock()
    total_ports = end_port - start_port + 1

    # Populate queue with ports
    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    # Setup progress bar
    progress = tqdm(total=total_ports, desc="Scanning ports", unit="port", file=open(os.devnull, 'w'))

    # Start scanning
    start_time = time.time()
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        for _ in range(max_threads):
            executor.submit(worker, ip, port_queue, results, lock, logger, progress)

    # Wait for all tasks to complete
    port_queue.join()
    progress.close()
    elapsed_time = time.time() - start_time

    # Process results
    open_ports = [port for port, is_open, _ in results if is_open]
    output = []
    if open_ports:
        result_text = f"Open ports: {', '.join(map(str, open_ports))}\n"
        output = [{"Port": port, "Status": "Open"} for port in open_ports]
        logger.info(result_text)
    else:
        result_text = "No open ports found\n"
        logger.info(result_text)
    
    summary = (f"Scanned {total_ports} ports in {elapsed_time:.2f} seconds\n"
               f"Average scan rate: {total_ports/elapsed_time:.2f} ports/second")
    logger.info(summary)
    
    update_callback(result_text + summary, output)
    complete_callback(None)

# GUI Application
class PortScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("EyE Port Scanner")
        self.root.geometry("800x600")
        
        # Initialize logger first
        self.logger = setup_logging()
        self.logger.debug("Initializing PortScannerApp")

        # Set custom icon for the window using iconbitmap
        try:
            # Handle PyInstaller bundled environment
            if getattr(sys, 'frozen', False):
                base_path = sys._MEIPASS
            else:
                base_path = os.path.dirname(__file__)
            icon_path = os.path.join(base_path, "scanner_icon.ico")
            self.root.iconbitmap(icon_path)
            self.logger.debug("Custom icon set successfully using iconbitmap")
        except Exception as e:
            self.logger.error(f"Failed to set custom icon: {str(e)}")

        self.style = ttkb.Style()
        self.settings = {
            "timeout": 1.0,
            "theme": "win11_light"
        }
        self.configure_win11_style()
        self.setup_gui()
        self.apply_theme()

    def configure_win11_style(self):
        # Custom Windows 11-inspired theme based on litera
        self.style.configure("TFrame", background="#F3F4F6")
        self.style.configure("TLabel", background="#F3F4F6", font=("Segoe UI", 11))
        self.style.configure("TEntry", font=("Segoe UI", 11), padding=5)
        self.style.configure("TButton", font=("Segoe UI", 11), padding=10)
        self.style.configure("TLabelframe", background="#F3F4F6", font=("Segoe UI", 11, "bold"))
        self.style.configure("TLabelframe.Label", background="#F3F4F6", foreground="black")
        self.style.configure("TCombobox", font=("Segoe UI", 11), padding=5)

        # Primary button (Windows 11 blue accent, polished)
        self.style.configure("primary.TButton", 
                            background="#005FB8", 
                            foreground="white", 
                            font=("Segoe UI", 11, "bold"),
                            borderwidth=0,
                            padding=10,
                            relief="flat")
        self.style.map("primary.TButton",
                      background=[("active", "#00205B"), ("!disabled", "hover", "#003087"), ("disabled", "#A3BFFA")],
                      foreground=[("disabled", "#666666")])

        # Secondary button (neutral gray, cohesive with primary)
        self.style.configure("secondary.TButton",
                            background="#E5E7EB",
                            foreground="black",
                            font=("Segoe UI", 11),
                            borderwidth=0,
                            padding=10,
                            relief="flat")
        self.style.map("secondary.TButton",
                      background=[("active", "#B0B7C0"), ("!disabled", "hover", "#D1D5DB"), ("disabled", "#F3F4F6")],
                      foreground=[("disabled", "#666666")])

        # Status bar
        self.style.configure("Status.TLabel", 
                           background="#E5E7EB", 
                           font=("Segoe UI", 10),
                           padding=5)

        # Simulate rounded corners with slight border radius (tkinter limitation)
        self.style.configure("TFrame", relief="flat")
        self.style.configure("TLabelframe", relief="flat", borderwidth=2, bordercolor="#D1D5DB")

    def setup_gui(self):
        self.logger.debug("Setting up GUI")
        # Main container with slight shadow effect
        self.main_frame = ttk.Frame(self.root, padding=10, style="TFrame")
        self.main_frame.pack(fill=BOTH, expand=True)

        # Input frame
        input_frame = ttk.LabelFrame(self.main_frame, text="Scan Parameters", padding=15, style="TLabelframe")
        input_frame.pack(fill=X, pady=10, padx=10)

        ttk.Label(input_frame, text="IP Address:", style="TLabel").grid(row=0, column=0, padx=10, pady=5, sticky=W)
        self.ip_entry = ttk.Entry(input_frame, style="TEntry")
        self.ip_entry.grid(row=0, column=1, padx=10, pady=5, sticky=EW)
        self.ip_entry.insert(0, "127.0.0.1")

        ttk.Label(input_frame, text="Start Port:", style="TLabel").grid(row=1, column=0, padx=10, pady=5, sticky=W)
        self.start_port_entry = ttk.Entry(input_frame, style="TEntry")
        self.start_port_entry.grid(row=1, column=1, padx=10, pady=5, sticky=EW)
        self.start_port_entry.insert(0, "1")

        ttk.Label(input_frame, text="End Port:", style="TLabel").grid(row=2, column=0, padx=10, pady=5, sticky=W)
        self.end_port_entry = ttk.Entry(input_frame, style="TEntry")
        self.end_port_entry.grid(row=2, column=1, padx=10, pady=5, sticky=EW)
        self.end_port_entry.insert(0, "1000")

        ttk.Label(input_frame, text="Threads:", style="TLabel").grid(row=3, column=0, padx=10, pady=5, sticky=W)
        self.threads_entry = ttk.Entry(input_frame, style="TEntry")
        self.threads_entry.grid(row=3, column=1, padx=10, pady=5, sticky=EW)
        self.threads_entry.insert(0, "100")

        input_frame.columnconfigure(1, weight=1)

        # Buttons frame
        buttons_frame = ttk.Frame(self.main_frame, style="TFrame")
        buttons_frame.pack(fill=X, pady=10, padx=10)
        self.scan_button = ttk.Button(buttons_frame, text="Start Scan", command=self.start_scan, style="primary.TButton")
        self.scan_button.pack(side=LEFT, padx=5)
        ttk.Button(buttons_frame, text="Settings", command=self.open_settings, style="secondary.TButton").pack(side=LEFT, padx=5)
        self.export_button = ttk.Button(buttons_frame, text="Export Results", command=self.export_results, style="secondary.TButton", state=DISABLED)
        self.export_button.pack(side=LEFT, padx=5)

        # Output frame
        output_frame = ttk.LabelFrame(self.main_frame, text="Scan Results", padding=15, style="TLabelframe")
        output_frame.pack(fill=BOTH, expand=True, pady=10, padx=10)

        self.output_text = tk.Text(
            output_frame, 
            height=15, 
            wrap=WORD, 
            font=("Segoe UI", 11), 
            bg="white", 
            fg="black", 
            bd=1, 
            relief="solid", 
            padx=5, 
            pady=5
        )
        self.output_text.pack(fill=BOTH, expand=True, padx=5, pady=5)
        scrollbar = ttk.Scrollbar(output_frame, orient=VERTICAL, command=self.output_text.yview)
        scrollbar.pack(side=RIGHT, fill=Y)
        self.output_text.config(yscrollcommand=scrollbar.set)

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self.main_frame, textvariable=self.status_var, style="Status.TLabel")
        status_bar.pack(fill=X, pady=5, padx=10)

    def apply_theme(self):
        self.logger.debug("Applying theme")
        self.style.theme_use("litera")  # Base theme, customized by configure_win11_style
        self.root.update_idletasks()

    def open_settings(self):
        self.logger.debug("Opening settings window")
        settings_window = ttkb.Toplevel(self.root)
        settings_window.title("Settings")
        settings_window.geometry("400x300")
        settings_window.transient(self.root)
        settings_window.grab_set()
        settings_window.configure(bg="#F3F4F6")

        # Set icon for settings window using iconbitmap
        try:
            # Handle PyInstaller bundled environment
            if getattr(sys, 'frozen', False):
                base_path = sys._MEIPASS
            else:
                base_path = os.path.dirname(__file__)
            icon_path = os.path.join(base_path, "scanner_icon.ico")
            settings_window.iconbitmap(icon_path)
            self.logger.debug("Custom icon set for settings window using iconbitmap")
        except Exception as e:
            self.logger.error(f"Failed to set custom icon for settings window: {str(e)}")

        frame = ttk.Frame(settings_window, padding=15, style="TFrame")
        frame.pack(fill=BOTH, expand=True)

        # Timeout setting
        ttk.Label(frame, text="Connection Timeout (seconds):", style="TLabel").pack(anchor=W, pady=5)
        timeout_entry = ttk.Entry(frame, style="TEntry")
        timeout_entry.insert(0, str(self.settings["timeout"]))
        timeout_entry.pack(fill=X, pady=5)

        # Theme selection (limited to light/dark for Windows 11 aesthetic)
        ttk.Label(frame, text="Theme:", style="TLabel").pack(anchor=W, pady=5)
        theme_combo = ttk.Combobox(frame, values=["win11_light", "win11_dark"], style="TCombobox")
        theme_combo.set(self.settings["theme"])
        theme_combo.pack(fill=X, pady=5)

        # Save button
        def save_settings():
            try:
                timeout = float(timeout_entry.get())
                if timeout <= 0:
                    messagebox.showerror("Error", "Timeout must be positive")
                    return
                self.settings["timeout"] = timeout
                new_theme = theme_combo.get()
                self.settings["theme"] = new_theme
                if new_theme == "win11_dark":
                    self.style.configure("TFrame", background="#202124")
                    self.style.configure("TLabel", background="#202124", foreground="white")
                    self.style.configure("TEntry", fieldbackground="#303134", foreground="white")
                    self.style.configure("TLabelframe", background="#202124", foreground="white")
                    self.style.configure("TLabelframe.Label", background="#202124", foreground="white")
                    self.style.configure("Status.TLabel", background="#303134", foreground="white")
                    self.style.configure("primary.TButton", 
                                        background="#005FB8", 
                                        foreground="white",
                                        relief="flat")
                    self.style.map("primary.TButton",
                                  background=[("active", "#00205B"), ("!disabled", "hover", "#003087"), ("disabled", "#A3BFFA")],
                                  foreground=[("disabled", "#666666")])
                    self.style.configure("secondary.TButton",
                                        background="#303134",
                                        foreground="white",
                                        relief="flat")
                    self.style.map("secondary.TButton",
                                  background=[("active", "#1C2526"), ("!disabled", "hover", "#252C2E"), ("disabled", "#3C4043")],
                                  foreground=[("disabled", "#666666")])
                    self.output_text.config(bg="#303134", fg="white")
                    settings_window.configure(bg="#202124")
                else:
                    self.style.configure("TFrame", background="#F3F4F6")
                    self.style.configure("TLabel", background="#F3F4F6", foreground="black")
                    self.style.configure("TEntry", fieldbackground="white", foreground="black")
                    self.style.configure("TLabelframe", background="#F3F4F6", foreground="black")
                    self.style.configure("TLabelframe.Label", background="#F3F4F6", foreground="black")
                    self.style.configure("Status.TLabel", background="#E5E7EB", foreground="black")
                    self.style.configure("primary.TButton", 
                                        background="#005FB8", 
                                        foreground="white",
                                        relief="flat")
                    self.style.map("primary.TButton",
                                  background=[("active", "#00205B"), ("!disabled", "hover", "#003087"), ("disabled", "#A3BFFA")],
                                  foreground=[("disabled", "#666666")])
                    self.style.configure("secondary.TButton",
                                        background="#E5E7EB",
                                        foreground="black",
                                        relief="flat")
                    self.style.map("secondary.TButton",
                                  background=[("active", "#B0B7C0"), ("!disabled", "hover", "#D1D5DB"), ("disabled", "#F3F4F6")],
                                  foreground=[("disabled", "#666666")])
                    self.output_text.config(bg="white", fg="black")
                    settings_window.configure(bg="#F3F4F6")
                self.apply_theme()
                settings_window.destroy()
                messagebox.showinfo("Success", "Settings saved")
            except ValueError:
                messagebox.showerror("Error", "Invalid timeout value")

        ttk.Button(frame, text="Save", command=save_settings, style="primary.TButton").pack(pady=10)
        ttk.Button(frame, text="Cancel", command=settings_window.destroy, style="secondary.TButton").pack(pady=5)

    def start_scan(self):
        self.logger.debug("Starting scan")
        try:
            ip = self.ip_entry.get().strip()
            start_port = int(self.start_port_entry.get())
            end_port = int(self.end_port_entry.get())
            threads = int(self.threads_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Please enter valid numeric values for ports and threads")
            self.logger.error("Invalid input for ports or threads")
            return

        if not ip:
            messagebox.showerror("Error", "IP address is required")
            self.logger.error("IP address missing")
            return
        if threads < 1:
            messagebox.showerror("Error", "Number of threads must be positive")
            self.logger.error("Invalid thread count")
            return

        self.scan_button.config(state=DISABLED)
        self.export_button.config(state=DISABLED)
        self.status_var.set("Scanning...")
        self.output_text.delete(1.0, tk.END)
        self.results_data = []

        def update_output(text, data):
            self.output_text.insert(tk.END, text)
            self.output_text.see(tk.END)
            self.results_data = data

        def complete_scan(error):
            self.scan_button.config(state=NORMAL)
            self.status_var.set("Ready" if not error else "Error")
            self.root.config(cursor="")
            if error:
                messagebox.showerror("Error", error)
                self.logger.error(f"Scan error: {error}")
            else:
                self.export_button.config(state=NORMAL)
                self.logger.info("Scan completed successfully")

        self.root.config(cursor="wait")
        threading.Thread(target=scan_ports, args=(ip, start_port, end_port, threads, 
                                                 update_output, complete_scan, self.logger), daemon=True).start()

    def export_results(self):
        self.logger.debug("Exporting results")
        if not self.results_data:
            messagebox.showwarning("Warning", "No results to export")
            self.logger.warning("No results to export")
            return

        filetypes = [
            ("Text files", "*.txt"),
            ("Excel files", "*.xlsx"),
            ("JSON files", "*.json"),
            ("All files", "*.*")
        ]
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=filetypes)
        if not file_path:
            self.logger.debug("Export cancelled by user")
            return

        try:
            if file_path.endswith(".txt"):
                with open(file_path, 'w') as f:
                    for item in self.results_data:
                        f.write(f"Port {item['Port']}: {item['Status']}\n")
            elif file_path.endswith(".xlsx"):
                df = pd.DataFrame(self.results_data)
                df.to_excel(file_path, index=False)
            elif file_path.endswith(".json"):
                with open(file_path, 'w') as f:
                    json.dump(self.results_data, f, indent=4)
            messagebox.showinfo("Success", "Results exported successfully")
            self.logger.info(f"Results exported to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export results: {str(e)}")
            self.logger.error(f"Export error: {str(e)}")

def main():
    logger = setup_logging()
    logger.debug("Starting application")
    try:
        root = ttkb.Window()
        app = PortScannerApp(root)
        root.mainloop()
    except Exception as e:
        logger.critical(f"Application failed to start: {str(e)}")
        print(f"Error: Application failed to start. Check port_scanner.log for details.")
        raise

if __name__ == "__main__":
    main()
