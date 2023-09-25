import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import csr_database
import os

def export_selected_csr():
    selected_item = certificates_treeview.selection()
    if not selected_item:
        messagebox.showerror("Error", "No certificate selected.")
        return

    common_name = certificates_treeview.item(selected_item, "values")[0]
    csr_data = certificates_treeview.item(selected_item, "values")[2]
    key_data = certificates_treeview.item(selected_item, "values")[3]

    export_path = filedialog.askdirectory()
    if export_path:
        csr_file_path = os.path.join(export_path, f"{common_name}.csr")
        key_file_path = os.path.join(export_path, f"{common_name}.key")

        with open(csr_file_path, "w") as csr_file:
            csr_file.write(csr_data)
        with open(key_file_path, "w") as key_file:
            key_file.write(key_data)

        messagebox.showinfo("Success", f"CSR and Key exported for '{common_name}'.")

def load_certificates(page_number):
    page_size = 10  # Number of certificates to display per page
    total_certificates = csr_database.get_total_certificate_count()
    total_pages = (total_certificates + page_size - 1) // page_size

    certificates_treeview.delete(*certificates_treeview.get_children())

    certificates = csr_database.get_certificates(page_number, page_size)
    for cert in certificates:
        certificates_treeview.insert("", "end", values=cert)

    page_label.config(text=f"Page {page_number} of {total_pages}")

def previous_page():
    current_page = int(page_label.cget("text").split()[-2])
    if current_page > 1:
        load_certificates(current_page - 1)
    else:
        messagebox.showinfo("Warning", f"Fist Page.")

def next_page():
    current_page = int(page_label.cget("text").split()[-2])
    total_pages = int(page_label.cget("text").split()[-1])
    if current_page < total_pages:
        load_certificates(current_page + 1)
    else:
        messagebox.showinfo("Warning", f"Last Page.")

# Create a Tkinter window
window = tk.Tk()
window.title("CSR Browser")

# Create and pack widgets
certificates_treeview = ttk.Treeview(window, columns=("Common Name", "ENV", "CSR", "Key", "Generated Date"))
certificates_treeview.heading("#1", text="Common Name")
certificates_treeview.heading("#2", text="ENV")
certificates_treeview.heading("#3", text="CSR")
certificates_treeview.heading("#4", text="Key")
certificates_treeview.heading("#5", text="Generated Date")
certificates_treeview.pack()

export_button = ttk.Button(window, text="Export Selected", command=export_selected_csr)
export_button.pack()

navigation_frame = ttk.Frame(window)
navigation_frame.pack()
previous_button = ttk.Button(navigation_frame, text="Previous", command=previous_page)
previous_button.grid(row=0, column=0)
page_label = ttk.Label(navigation_frame, text="Page 1 of 1")
page_label.grid(row=0, column=1)
next_button = ttk.Button(navigation_frame, text="Next", command=next_page)
next_button.grid(row=0, column=2)

load_certificates(1)  # Load the first page of certificates

# Start the Tkinter main loop
window.mainloop()
