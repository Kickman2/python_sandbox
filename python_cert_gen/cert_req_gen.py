import os
import sys
from OpenSSL import crypto
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

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
    output_path = output_path_entry.get()
    key_passphrase = key_passphrase_entry.get()
    multi = multi_checkbox_var.get()

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

    with open(key_file, "wb") as keyfile:
        keyfile.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key, cipher="aes-256-cbc", passphrase=key_passphrase.encode()))

    with open(csr_file, "wb") as csrfile:
        csrfile.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, req))

    messagebox.showinfo("Success", f"Certificate request for '{common_name}' generated successfully!")

# Create a Tkinter window
window = tk.Tk()
window.title("Certificate Request Generator")

# Create and pack widgets
common_name_label = ttk.Label(window, text="Common Name:")
common_name_label.pack()
common_name_entry = ttk.Entry(window)
common_name_entry.pack()

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

generate_button = ttk.Button(window, text="Generate Certificate Request", command=generate_certificate_request_gui)
generate_button.pack()

# Start the Tkinter main loop
window.mainloop()
