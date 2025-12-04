import tkinter as tk
from tkinter import messagebox
import random

def generate_password():
    try:
        # Get character type counts
        lower = int(lower_entry.get() or 0)
        upper = int(upper_entry.get() or 0)
        nums = int(number_entry.get() or 0)
        syms = int(symbol_entry.get() or 0)
        total_required = lower + upper + nums + syms

        # Get total length
        total_length = int(length_entry.get())

        if total_length < total_required:
            messagebox.showwarning("Warning", "Length must be at least equal to total character counts.")
            result_entry.delete(0, tk.END)
            return
        if total_length < 4:
            messagebox.showwarning("Warning", "Password length should be at least 4.")
            result_entry.delete(0, tk.END)
            return

        # Character sets
        lowercase = 'abcdefghijklmnopqrstuvwxyz'
        uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        digits = '0123456789'
        symbols = '@#$^&*-_!'

        # Build password characters
        password_chars = (
            [random.choice(lowercase) for _ in range(lower)] +
            [random.choice(uppercase) for _ in range(upper)] +
            [random.choice(digits) for _ in range(nums)] +
            [random.choice(symbols) for _ in range(syms)]
        )

        # Determine used categories
        used_categories = []
        if lower > 0: used_categories.append('lower')
        if upper > 0: used_categories.append('upper')
        if nums > 0: used_categories.append('num')
        if syms > 0: used_categories.append('sym')

        category_map = {
            'lower': lowercase,
            'upper': uppercase,
            'num': digits,
            'sym': symbols
        }

        # Exclude used categories for remaining characters
        available_categories = [k for k in category_map if k not in used_categories]

        if not available_categories:
            remaining_chars = lowercase + uppercase + digits + symbols
        else:
            remaining_chars = ''.join(category_map[k] for k in available_categories)

        remaining = total_length - len(password_chars)
        password_chars += [random.choice(remaining_chars) for _ in range(remaining)]

        random.shuffle(password_chars)
        password = ''.join(password_chars)

        result_entry.delete(0, tk.END)
        result_entry.insert(0, password)

    except ValueError:
        messagebox.showerror("Error", "Please enter valid numbers.")
        result_entry.delete(0, tk.END)

def copy_password():
    password = result_entry.get()
    if password:
        root.clipboard_clear()
        root.clipboard_append(password)
        messagebox.showinfo("Copied", "Password copied to clipboard!")
    else:
        messagebox.showwarning("Warning", "No password to copy.")

def clear_fields():
    for entry in [length_entry, lower_entry, upper_entry, number_entry, symbol_entry, result_entry]:
        entry.delete(0, tk.END)

# GUI setup
root = tk.Tk()
root.title("🔧 Custom Password Generator")
root.geometry("550x500")
root.configure(bg="#f0f4f8")
root.resizable(False, False)
# Font styles

font_label = ("Helvetica", 12)
font_entry = ("Helvetica", 12)
font_button = ("Helvetica", 11, "bold")
button_font = ("Helvetica", 11, "bold")

# Length input
tk.Label(root, text="Total Password Length:", font=font_label, bg="#f0f4f8").grid(row=0, column=0, padx=10, pady=10, sticky="e")
length_entry = tk.Entry(root, font=font_entry, width=5)
length_entry.grid(row=0, column=1, pady=10, sticky="w")

# Character counts
tk.Label(root, text="Lowercase Letters:", font=font_label, bg="#f0f4f8").grid(row=1, column=0, padx=10, pady=5, sticky="e")
lower_entry = tk.Entry(root, font=font_entry, width=5)
lower_entry.grid(row=1, column=1, pady=5, sticky="w")

tk.Label(root, text="Uppercase Letters:", font=font_label, bg="#f0f4f8").grid(row=2, column=0, padx=10, pady=5, sticky="e")
upper_entry = tk.Entry(root, font=font_entry, width=5)
upper_entry.grid(row=2, column=1, pady=5, sticky="w")

tk.Label(root, text="Numbers:", font=font_label, bg="#f0f4f8").grid(row=3, column=0, padx=10, pady=5, sticky="e")
number_entry = tk.Entry(root, font=font_entry, width=5)
number_entry.grid(row=3, column=1, pady=5, sticky="w")

tk.Label(root, text="Symbols:", font=font_label, bg="#f0f4f8").grid(row=4, column=0, padx=10, pady=5, sticky="e")
symbol_entry = tk.Entry(root, font=font_entry, width=5)
symbol_entry.grid(row=4, column=1, pady=5, sticky="w")

# Generate Button
generate_btn = tk.Button(root, text="Generate Password", font=button_font, bg="#4CAF50", fg="white", padx=10, pady=5, command=generate_password)
generate_btn.grid(row=5, column=0, columnspan=2, pady=10)

# Output
tk.Label(root, text="Generated Password:", font=font_label, bg="#f0f4f8").grid(row=6, column=0, padx=10, pady=10, sticky="e")
result_entry = tk.Entry(root, font=font_entry, width=35, fg="#333", bg="#e8f0fe")
result_entry.grid(row=6, column=1, pady=10, sticky="w")

# Copy Button
copy_btn = tk.Button(root, text="Copy Password", font=button_font, bg="#2196F3", fg="white", padx=10, pady=5, command=copy_password)
copy_btn.grid(row=7, column=0, columnspan=2, pady=10)

root.mainloop()
