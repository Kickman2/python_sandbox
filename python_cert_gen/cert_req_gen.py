import os
import sys
from OpenSSL import crypto
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime, timedelta
import csr_database

def on_closing():
    csr_database.close_database()
    window.destroy()

def set_attribute(subj, common_name):
    subj.CN = common_name
    subj.C = "SG"
    subj.ST = "example"
    subj.L = "example"
    subj.O = "example ltd"
    subj.OU = "exampleou"
    subj.emailAddress = "cert_admin@example.com"
    return subj

def browse_output_path():
    selected_path = filedialog.askdirectory()
    output_path_entry.delete(0, tk.END)  # Clear the current path
    output_path_entry.insert(0, selected_path)  # Insert the selected path

def generate_certificate_request_gui():
    common_name = common_name_entry.get()
    env = env_entry.get()
    output_path = output_path_entry.get()
    key_passphrase = key_passphrase_entry.get()
    multi = multi_checkbox_var.get()
    expire = expiration_days_checkbox_var.get()
    

    if not os.path.isdir(output_path):
        messagebox.showerror("Error", f"The specified path '{output_path}' does not exist.")
        return

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    key_file = os.path.join(output_path, common_name + ".key")
    csr_file = os.path.join(output_path, common_name + ".csr")

    req = crypto.X509Req()
    subj = req.get_subject()
    subj = set_attribute(subj, common_name)

    req.set_pubkey(key)

    if multi:
        san = ",".join(["DNS:" + domain.strip() for domain in multi_domains_entry.get().split(",")])
        req.add_extensions([crypto.X509Extension(b"subjectAltName", False, san.encode())])

    req.sign(key, "sha256")

    cert = crypto.X509()
    cert.set_serial_number(1000)
    if expire:
        expiration_days = int(expiration_days_entry.get())
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(expiration_days * 24 * 60 * 60)
    cert.set_issuer(req.get_subject())
    cert.set_subject(req.get_subject())
    cert.set_pubkey(req.get_pubkey())
    cert.sign(key, "sha256")

    key_data = crypto.dump_privatekey(crypto.FILETYPE_PEM, key, cipher="aes-256-cbc", passphrase=key_passphrase.encode())
    csr_data = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)
    with open(key_file, "wb") as keyfile:
        keyfile.write(key_data)


    with open(csr_file, "wb") as csrfile:
        csrfile.write(csr_data)

    csr_database.insert_certificate(common_name, env, csr_data, key_data)
    messagebox.showinfo("Success", f"Certificate request for '{common_name}' generated successfully")

# Create a Tkinter window
window = tk.Tk()
window.title("Certificate Generator")

screen_width = window.winfo_screenwidth()
screen_height = window.winfo_screenheight()

# Set the window size (80% of screen width and height)
window_width = int(screen_width * 0.4)
window_height = int(screen_height * 0.4)
window_size = f"{window_width}x{window_height}"
window.geometry(window_size)

# Calculate the x and y positions to center the window
x_pos = (screen_width - window_width) // 2
y_pos = (screen_height - window_height) // 2
window.geometry(f"+{x_pos}+{y_pos}")

# Create and pack widgets
common_name_label = ttk.Label(window, text="Common Name:")
common_name_label.pack()
common_name_entry = ttk.Entry(window)
common_name_entry.pack()

env_label = ttk.Label(window, text="Env:")
env_label.pack()
env_entry = ttk.Entry(window)
env_entry.pack()

output_path_label = ttk.Label(window, text="Output Path:")
output_path_label.pack()
output_path_entry = ttk.Entry(window)
output_path_entry.pack()

browse_button = ttk.Button(window, text="Browse", command=browse_output_path)
browse_button.pack()

key_passphrase_label = ttk.Label(window, text="Key Passphrase:")
key_passphrase_label.pack()
key_passphrase_entry = ttk.Entry(window, show="*")
key_passphrase_entry.pack()

multi_checkbox_var = tk.BooleanVar()
multi_checkbox = ttk.Checkbutton(window, text="Generate for multiple domains", variable=multi_checkbox_var)
multi_checkbox.pack()

multi_domains_label = ttk.Label(window, text="Enter multiple domains separated by commas:")
multi_domains_label.pack()
multi_domains_entry = ttk.Entry(window)
multi_domains_entry.pack()

expiration_days_checkbox_var = tk.BooleanVar()
expiration_days_checkbox = ttk.Checkbutton(window, text="Set expire date", variable=expiration_days_checkbox_var)
expiration_days_checkbox.pack()

expiration_days_label = ttk.Label(window, text="Expiration Days:")
expiration_days_label.pack()
expiration_days_entry = ttk.Entry(window)
expiration_days_entry.insert(0, "365")  # Default to 365 days
expiration_days_entry.pack()

generate_button = ttk.Button(window, text="Generate Certificate Request", command=generate_certificate_request_gui)
generate_button.pack()

window.protocol("WM_DELETE_WINDOW", lambda: on_closing())
# Start the Tkinter main loop
window.mainloop()

