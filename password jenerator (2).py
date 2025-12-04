import tkinter as tk
from tkinter import messagebox, ttk
import random

# Function to generate password
def generate_password():
    try:
        length = int(length_entry.get())
        if length < 4:
            messagebox.showwarning("Warning", "Password length should be at least 4.")
            return

        category = category_var.get()

        # Character sets declared manually
        lowercase = 'abcdefghijklmnopqrstuvwxyz'
        uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        digits = '0123456789'
        symbols = '@#$^&*-_!'

        # Category-based character selection
        if category == "Lowercase Only":
            characters = lowercase
        elif category == "Uppercase Only":
            characters = uppercase
        elif category == "Numbers Only":
            characters = digits
        elif category == "Symbols Only":
            characters = symbols
        elif category == "Lowercase + Numbers":
            characters = lowercase + digits
        elif category == "Uppercase + Numbers":
            characters = uppercase + digits
        elif category == "Uppercase + Symbols":
            characters = uppercase +symbols
        elif category == "Lowercase + Symbols":
            characters = lowercase +symbols
        elif category == "Numbers + Symbols":
            characters = digits + symbols
        elif category == "Letters Only":
            characters = lowercase + uppercase
        elif category == "Letters + Numbers":
            characters = lowercase + uppercase + digits
        elif category == "Letters + Symbols":
            characters = lowercase + uppercase + symbols
        else:  # All Characters
            characters = lowercase + uppercase + digits + symbols

        password = ''.join(random.choice(characters) for _ in range(length))
        result_entry.delete(0, tk.END)
        result_entry.insert(0, password)

    except ValueError:
        messagebox.showerror("Error", "Please enter a valid number.")

# Copy to clipboard
def copy_password():
    password = result_entry.get()
    if password:
        root.clipboard_clear()
        root.clipboard_append(password)
        messagebox.showinfo("Copied", "Password copied to clipboard!")
    else:
        messagebox.showwarning("Warning", "No password to copy.")

# GUI setup
root = tk.Tk()
root.title("🔐 Custom Password Generator")
root.geometry("580x340")
root.resizable(False, False)
root.configure(bg="#f0f4f8")

# Font styles
label_font = ("Helvetica", 12, "italic")
entry_font = ("Helvetica", 12)
button_font = ("Helvetica", 11, "bold")

# Layout: Password Length
tk.Label(root, text="Password Length:", font=label_font, bg="#f0f4f8").grid(row=0, column=0, pady=15, padx=10, sticky="e")
length_entry = tk.Entry(root, font=entry_font, width=10)
length_entry.grid(row=0, column=1, pady=15, sticky="w")

# Layout: Category Dropdown
tk.Label(root, text="Password Type:", font=label_font, bg="#f0f4f8").grid(row=1, column=0, pady=10, padx=10, sticky="e")
category_var = tk.StringVar(value="All Characters")
category_dropdown = ttk.Combobox(
    root,
    textvariable=category_var,
    values=[
        "Lowercase Only",
        "Uppercase Only",
        "Numbers Only",
        "Symbols Only",
        "Lowercase + Numbers",
        "Uppercase + Numbers",
        "Uppercase + Symbols",
        "Lowercase + Symbols",
        "Numbers + Symbols",
        "Letters Only",
        "Letters + Numbers",
        "Letters + Symbols",
        "All Characters"
    ],
    state="readonly",
    width=25
)
category_dropdown.grid(row=1, column=1, pady=10, sticky="w")

# Generate Button
generate_btn = tk.Button(root, text="Generate Password", font=button_font, bg="#4CAF50", fg="white", padx=10, pady=5, command=generate_password)
generate_btn.grid(row=2, column=0, columnspan=2, pady=10)

# Layout: Generated Password
tk.Label(root, text="Generated Password:", font=label_font, bg="#f0f4f8").grid(row=3, column=0, pady=10, padx=10, sticky="e")
result_entry = tk.Entry(root, font=entry_font, width=35, fg="#333", bg="#e8f0fe")
result_entry.grid(row=3, column=1, pady=10, sticky="w")

# Copy Button
copy_btn = tk.Button(root, text="Copy Password", font=button_font, bg="#2196F3", fg="white", padx=10, pady=5, command=copy_password)
copy_btn.grid(row=4, column=0, columnspan=2, pady=10)

# Run the application
root.mainloop()
