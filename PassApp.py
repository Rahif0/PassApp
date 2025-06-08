import streamlit as st
import sqlite3
import hashlib
import secrets
import string
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import pandas as pd
from datetime import datetime


class PasswordManager:
    def __init__(self):
        self.master_key = None
        self.cipher_suite = None
        self.db_file = "passwords.db"
        self.setup_database()

    def setup_database(self):
        """Initialize the database"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS master_password (
                    id INTEGER PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    site_name TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL,
                    notes TEXT,
                    created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            conn.commit()
        except sqlite3.Error as e:
            print(f"Database error: {e}")
        finally:
            conn.close()

    def derive_key(self, password, salt):
        """Derive encryption key from master password"""
        password = password.encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key

    def set_master_password(self, password):
        """Set and store master password"""
        try:
            salt = os.urandom(16)
            password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM master_password')
            cursor.execute('INSERT INTO master_password (id, password_hash, salt) VALUES (?, ?, ?)',
                           (1, base64.b64encode(password_hash).decode(), base64.b64encode(salt).decode()))
            conn.commit()

            self.master_key = self.derive_key(password, salt)
            self.cipher_suite = Fernet(self.master_key)
            return True
        except Exception as e:
            print(f"Error setting master password: {e}")
            return False
        finally:
            conn.close()

    def verify_master_password(self, password):
        """Verify master password and set up encryption"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute('SELECT password_hash, salt FROM master_password WHERE id=1')
            result = cursor.fetchone()

            if not result:
                return False

            stored_hash = base64.b64decode(result[0])
            salt = base64.b64decode(result[1])

            password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

            if password_hash == stored_hash:
                self.master_key = self.derive_key(password, salt)
                self.cipher_suite = Fernet(self.master_key)
                return True
            return False
        except Exception as e:
            print(f"Error verifying master password: {e}")
            return False
        finally:
            conn.close()

    def has_master_password(self):
        """Check if master password exists"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM master_password WHERE id=1')
            count = cursor.fetchone()[0]
            return count > 0
        except sqlite3.Error as e:
            print(f"Database error in has_master_password: {e}")
            return False
        finally:
            conn.close()

    def encrypt_password(self, password):
        """Encrypt password"""
        return self.cipher_suite.encrypt(password.encode()).decode()

    def decrypt_password(self, encrypted_password):
        """Decrypt password"""
        try:
            return self.cipher_suite.decrypt(encrypted_password.encode()).decode()
        except Exception as e:
            print(f"Decryption error: {e}")
            return "DECRYPTION ERROR"

    def add_password(self, site_name, username, password, notes=""):
        """Add new password entry"""
        try:
            encrypted_password = self.encrypt_password(password)

            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO passwords (site_name, username, password, notes)
                VALUES (?, ?, ?, ?)
            ''', (site_name, username, encrypted_password, notes))
            conn.commit()
            return True
        except Exception as e:
            print(f"Error adding password: {e}")
            return False
        finally:
            conn.close()

    def get_all_passwords(self):
        """Get all password entries"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute('SELECT id, site_name, username, password, notes, created_date FROM passwords')
            results = cursor.fetchall()

            decrypted_results = []
            for row in results:
                decrypted_password = self.decrypt_password(row[3])
                decrypted_row = list(row)
                decrypted_row[3] = decrypted_password
                decrypted_results.append(decrypted_row)
            return decrypted_results
        except Exception as e:
            print(f"Error getting passwords: {e}")
            return []
        finally:
            conn.close()

    def update_password(self, password_id, site_name, username, password, notes=""):
        """Update existing password entry"""
        try:
            encrypted_password = self.encrypt_password(password)

            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE passwords SET site_name=?, username=?, password=?, notes=?
                WHERE id=?
            ''', (site_name, username, encrypted_password, notes, password_id))
            conn.commit()
            return True
        except Exception as e:
            print(f"Error updating password: {e}")
            return False
        finally:
            conn.close()

    def delete_password(self, password_id):
        """Delete password entry"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM passwords WHERE id=?', (password_id,))
            conn.commit()
            return True
        except Exception as e:
            print(f"Error deleting password: {e}")
            return False
        finally:
            conn.close()

    def generate_password(self, length=16, include_symbols=True):
        """Generate a secure random password"""
        characters = string.ascii_letters + string.digits
        if include_symbols:
            characters += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        return ''.join(secrets.choice(characters) for _ in range(length))


class PasswordManagerGUI:
    def __init__(self):
        self.pm = PasswordManager()
        self.root = tk.Tk()
        self.root.title("Secure Password Manager")
        self.root.geometry("800x600")
        self.root.configure(bg='#2c3e50')

        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('Title.TLabel', font=('Arial', 16, 'bold'), background='#2c3e50', foreground='white')
        self.style.configure('Custom.TButton', font=('Arial', 10))

        self.authenticated = False
        self.setup_login_screen()

    def setup_login_screen(self):
        """Setup initial login/setup screen"""
        for widget in self.root.winfo_children():
            widget.destroy()

        main_frame = tk.Frame(self.root, bg='#2c3e50')
        main_frame.pack(expand=True, fill='both', padx=20, pady=20)

        title_label = tk.Label(main_frame, text="🔐 Secure Password Manager",
                               font=('Arial', 24, 'bold'), bg='#2c3e50', fg='white')
        title_label.pack(pady=30)

        login_frame = tk.Frame(main_frame, bg='#34495e', padx=30, pady=30)
        login_frame.pack(expand=True, fill='both', padx=50, pady=50)

        if not self.pm.has_master_password():
            setup_label = tk.Label(login_frame, text="Set up your Master Password",
                                   font=('Arial', 16, 'bold'), bg='#34495e', fg='white')
            setup_label.pack(pady=20)

            tk.Label(login_frame, text="Master Password:", bg='#34495e', fg='white').pack(pady=5)
            self.master_password_entry = tk.Entry(login_frame, show="*", font=('Arial', 12), width=30)
            self.master_password_entry.pack(pady=5)

            tk.Label(login_frame, text="Confirm Password:", bg='#34495e', fg='white').pack(pady=5)
            self.confirm_password_entry = tk.Entry(login_frame, show="*", font=('Arial', 12), width=30)
            self.confirm_password_entry.pack(pady=5)

            setup_btn = tk.Button(login_frame, text="Create Master Password",
                                  command=self.setup_master_password,
                                  bg='#27ae60', fg='white', font=('Arial', 12, 'bold'),
                                  padx=20, pady=10)
            setup_btn.pack(pady=20)
        else:
            login_label = tk.Label(login_frame, text="Enter your Master Password",
                                   font=('Arial', 16, 'bold'), bg='#34495e', fg='white')
            login_label.pack(pady=20)

            tk.Label(login_frame, text="Master Password:", bg='#34495e', fg='white').pack(pady=5)
            self.master_password_entry = tk.Entry(login_frame, show="*", font=('Arial', 12), width=30)
            self.master_password_entry.pack(pady=5)
            self.master_password_entry.bind('<Return>', lambda e: self.login())

            login_btn = tk.Button(login_frame, text="Login",
                                  command=self.login,
                                  bg='#3498db', fg='white', font=('Arial', 12, 'bold'),
                                  padx=20, pady=10)
            login_btn.pack(pady=20)

        self.master_password_entry.focus()

    def setup_master_password(self):
        """Setup new master password"""
        password = self.master_password_entry.get()
        confirm = self.confirm_password_entry.get()

        if len(password) < 8:
            messagebox.showerror("Error", "Master password must be at least 8 characters long!")
            return

        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match!")
            return

        if self.pm.set_master_password(password):
            messagebox.showinfo("Success",
                                "Master password created successfully!\nPlease remember it, as it cannot be recovered if forgotten.")
            self.authenticated = True
            self.setup_main_screen()
        else:
            messagebox.showerror("Error", "Failed to create master password! Please try again.")

    def login(self):
        """Login with master password"""
        password = self.master_password_entry.get()

        if self.pm.verify_master_password(password):
            self.authenticated = True
            self.setup_main_screen()
        else:
            messagebox.showerror("Error", "Invalid master password!")
            self.master_password_entry.delete(0, tk.END)

    def setup_main_screen(self):
        """Setup main password manager interface"""
        for widget in self.root.winfo_children():
            widget.destroy()

        main_container = tk.Frame(self.root, bg='#2c3e50')
        main_container.pack(fill='both', expand=True, padx=10, pady=10)

        top_frame = tk.Frame(main_container, bg='#2c3e50')
        top_frame.pack(fill='x', pady=(0, 10))

        title_label = tk.Label(top_frame, text="🔐 Password Manager",
                               font=('Arial', 18, 'bold'), bg='#2c3e50', fg='white')
        title_label.pack(side='left')

        btn_frame = tk.Frame(top_frame, bg='#2c3e50')
        btn_frame.pack(side='right')

        add_btn = tk.Button(btn_frame, text="➕ Add Password",
                            command=self.add_password_dialog,
                            bg='#27ae60', fg='white', font=('Arial', 10, 'bold'))
        add_btn.pack(side='left', padx=5)

        generate_btn = tk.Button(btn_frame, text="🎲 Generate Password",
                                 command=self.generate_password_dialog,
                                 bg='#9b59b6', fg='white', font=('Arial', 10, 'bold'))
        generate_btn.pack(side='left', padx=5)

        logout_btn = tk.Button(btn_frame, text="🚪 Logout",
                               command=self.logout,
                               bg='#e74c3c', fg='white', font=('Arial', 10, 'bold'))
        logout_btn.pack(side='left', padx=5)

        search_frame = tk.Frame(main_container, bg='#2c3e50')
        search_frame.pack(fill='x', pady=(0, 10))

        tk.Label(search_frame, text="🔍 Search:", bg='#2c3e50', fg='white', font=('Arial', 12)).pack(side='left')
        self.search_var = tk.StringVar()
        self.search_var.trace('w', self.filter_passwords)
        search_entry = tk.Entry(search_frame, textvariable=self.search_var, font=('Arial', 12), width=30)
        search_entry.pack(side='left', padx=10)

        tree_frame = tk.Frame(main_container, bg='#2c3e50')
        tree_frame.pack(fill='both', expand=True)

        v_scrollbar = ttk.Scrollbar(tree_frame)
        v_scrollbar.pack(side='right', fill='y')

        h_scrollbar = ttk.Scrollbar(tree_frame, orient='horizontal')
        h_scrollbar.pack(side='bottom', fill='x')

        self.tree = ttk.Treeview(tree_frame, columns=('Site', 'Username', 'Password', 'Notes', 'Date'),
                                 show='headings', yscrollcommand=v_scrollbar.set,
                                 xscrollcommand=h_scrollbar.set)

        v_scrollbar.config(command=self.tree.yview)
        h_scrollbar.config(command=self.tree.xview)

        self.tree.heading('Site', text='Site Name')
        self.tree.heading('Username', text='Username')
        self.tree.heading('Password', text='Password')
        self.tree.heading('Notes', text='Notes')
        self.tree.heading('Date', text='Created Date')

        self.tree.column('Site', width=150)
        self.tree.column('Username', width=150)
        self.tree.column('Password', width=150)
        self.tree.column('Notes', width=200)
        self.tree.column('Date', width=150)

        self.tree.pack(fill='both', expand=True)

        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="📋 Copy Password", command=self.copy_password)
        self.context_menu.add_command(label="👁️ Show Password", command=self.show_password)
        self.context_menu.add_command(label="✏️ Edit", command=self.edit_password)
        self.context_menu.add_command(label="🗑️ Delete", command=self.delete_password)

        self.tree.bind("<Button-3>", self.show_context_menu)
        self.tree.bind("<Double-1>", self.show_password)

        self.refresh_password_list()

    def add_password_dialog(self):
        """Show add password dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Add New Password")
        dialog.geometry("400x300")
        dialog.configure(bg='#34495e')
        dialog.transient(self.root)
        dialog.grab_set()

        dialog.geometry("+%d+%d" % (self.root.winfo_rootx() + 50, self.root.winfo_rooty() + 50))

        tk.Label(dialog, text="Site Name:", bg='#34495e', fg='white').pack(pady=5)
        site_entry = tk.Entry(dialog, font=('Arial', 12), width=40)
        site_entry.pack(pady=5)

        tk.Label(dialog, text="Username:", bg='#34495e', fg='white').pack(pady=5)
        username_entry = tk.Entry(dialog, font=('Arial', 12), width=40)
        username_entry.pack(pady=5)

        tk.Label(dialog, text="Password:", bg='#34495e', fg='white').pack(pady=5)
        password_frame = tk.Frame(dialog, bg='#34495e')
        password_frame.pack(pady=5)

        password_entry = tk.Entry(password_frame, font=('Arial', 12), width=30)
        password_entry.pack(side='left', padx=5)

        generate_btn = tk.Button(password_frame, text="Generate",
                                 command=lambda: self.generate_and_fill(password_entry),
                                 bg='#9b59b6', fg='white')
        generate_btn.pack(side='left')

        tk.Label(dialog, text="Notes (optional):", bg='#34495e', fg='white').pack(pady=5)
        notes_entry = tk.Text(dialog, font=('Arial', 10), width=40, height=4)
        notes_entry.pack(pady=5)

        btn_frame = tk.Frame(dialog, bg='#34495e')
        btn_frame.pack(pady=20)

        save_btn = tk.Button(btn_frame, text="Save",
                             command=lambda: self.save_password(dialog, site_entry.get(),
                                                                username_entry.get(), password_entry.get(),
                                                                notes_entry.get("1.0", tk.END).strip()),
                             bg='#27ae60', fg='white', font=('Arial', 12, 'bold'))
        save_btn.pack(side='left', padx=10)

        cancel_btn = tk.Button(btn_frame, text="Cancel",
                               command=dialog.destroy,
                               bg='#e74c3c', fg='white', font=('Arial', 12, 'bold'))
        cancel_btn.pack(side='left', padx=10)

        site_entry.focus()

    def logout(self):
        """Logout and return to login screen"""
        self.authenticated = False
        self.setup_login_screen()

    def show_context_menu(self, event):
        """Show context menu on right click"""
        item = self.tree.selection()[0] if self.tree.selection() else None
        if item:
            self.context_menu.post(event.x_root, event.y_root)

    def refresh_password_list(self):
        """Refresh the password list"""
        for item in self.tree.get_children():
            self.tree.delete(item)

        passwords = self.pm.get_all_passwords()
        for password in passwords:
            display_password = '*' * 12
            self.tree.insert('', 'end', values=(
                password[1],
                password[2],
                display_password,
                password[4] if password[4] else '',
                password[5][:10] if password[5] else ''
            ), tags=(password[0],))

    def filter_passwords(self, *args):
        """Filter passwords based on search"""
        search_term = self.search_var.get().lower()

        for item in self.tree.get_children():
            self.tree.delete(item)

        passwords = self.pm.get_all_passwords()
        for password in passwords:
            if (search_term in password[1].lower() or
                    search_term in password[2].lower() or
                    (password[4] and search_term in password[4].lower())):
                display_password = '*' * 12
                self.tree.insert('', 'end', values=(
                    password[1],
                    password[2],
                    display_password,
                    password[4] if password[4] else '',
                    password[5][:10] if password[5] else ''
                ), tags=(password[0],))

    def generate_and_fill(self, entry_widget):
        """Generate password and fill entry widget"""
        password = self.pm.generate_password()
        entry_widget.delete(0, tk.END)
        entry_widget.insert(0, password)

    def save_password(self, dialog, site_name, username, password, notes):
        """Save new password"""
        if not site_name or not username or not password:
            messagebox.showerror("Error", "Please fill in all required fields!")
            return

        if self.pm.add_password(site_name, username, password, notes):
            messagebox.showinfo("Success", "Password saved successfully!")
            dialog.destroy()
            self.refresh_password_list()
        else:
            messagebox.showerror("Error", "Failed to save password!")

    def copy_password(self):
        """Copy password to clipboard"""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Please select a password entry!")
            return

        password_id = self.tree.item(selected_item[0])['tags'][0]
        passwords = self.pm.get_all_passwords()

        for password in passwords:
            if password[0] == password_id:
                pyperclip.copy(password[3])
                messagebox.showinfo("Success", "Password copied to clipboard!")
                break

    def show_password(self, event=None):
        """Show password in a dialog"""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Please select a password entry!")
            return

        password_id = self.tree.item(selected_item[0])['tags'][0]
        passwords = self.pm.get_all_passwords()

        for password in passwords:
            if password[0] == password_id:
                messagebox.showinfo("Password", f"Password for {password[1]}:\n{password[3]}")
                break

    def edit_password(self):
        """Edit selected password"""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Please select a password entry!")
            return

        password_id = self.tree.item(selected_item[0])['tags'][0]
        passwords = self.pm.get_all_passwords()

        current_password = None
        for password in passwords:
            if password[0] == password_id:
                current_password = password
                break

        if not current_password:
            return

        dialog = tk.Toplevel(self.root)
        dialog.title("Edit Password")
        dialog.geometry("400x300")
        dialog.configure(bg='#34495e')
        dialog.transient(self.root)
        dialog.grab_set()

        tk.Label(dialog, text="Site Name:", bg='#34495e', fg='white').pack(pady=5)
        site_entry = tk.Entry(dialog, font=('Arial', 12), width=40)
        site_entry.pack(pady=5)
        site_entry.insert(0, current_password[1])

        tk.Label(dialog, text="Username:", bg='#34495e', fg='white').pack(pady=5)
        username_entry = tk.Entry(dialog, font=('Arial', 12), width=40)
        username_entry.pack(pady=5)
        username_entry.insert(0, current_password[2])

        tk.Label(dialog, text="Password:", bg='#34495e', fg='white').pack(pady=5)
        password_frame = tk.Frame(dialog, bg='#34495e')
        password_frame.pack(pady=5)

        password_entry = tk.Entry(password_frame, font=('Arial', 12), width=30)
        password_entry.pack(side='left', padx=5)
        password_entry.insert(0, current_password[3])

        generate_btn = tk.Button(password_frame, text="Generate",
                                 command=lambda: self.generate_and_fill(password_entry),
                                 bg='#9b59b6', fg='white')
        generate_btn.pack(side='left')

        tk.Label(dialog, text="Notes:", bg='#34495e', fg='white').pack(pady=5)
        notes_entry = tk.Text(dialog, font=('Arial', 10), width=40, height=4)
        notes_entry.pack(pady=5)
        if current_password[4]:
            notes_entry.insert("1.0", current_password[4])

        btn_frame = tk.Frame(dialog, bg='#34495e')
        btn_frame.pack(pady=20)

        update_btn = tk.Button(btn_frame, text="Update",
                               command=lambda: self.update_password(dialog, password_id,
                                                                    site_entry.get(), username_entry.get(),
                                                                    password_entry.get(),
                                                                    notes_entry.get("1.0", tk.END).strip()),
                               bg='#27ae60', fg='white', font=('Arial', 12, 'bold'))
        update_btn.pack(side='left', padx=10)

        cancel_btn = tk.Button(btn_frame, text="Cancel",
                               command=dialog.destroy,
                               bg='#e74c3c', fg='white', font=('Arial', 12, 'bold'))
        cancel_btn.pack(side='left', padx=10)

    def update_password(self, dialog, password_id, site_name, username, password, notes):
        """Update existing password"""
        if not site_name or not username or not password:
            messagebox.showerror("Error", "Please fill in all required fields!")
            return

        if self.pm.update_password(password_id, site_name, username, password, notes):
            messagebox.showinfo("Success", "Password updated successfully!")
            dialog.destroy()
            self.refresh_password_list()
        else:
            messagebox.showerror("Error", "Failed to update password!")

    def delete_password(self):
        """Delete selected password"""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Please select a password entry!")
            return

        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this password?"):
            password_id = self.tree.item(selected_item[0])['tags'][0]
            if self.pm.delete_password(password_id):
                messagebox.showinfo("Success", "Password deleted successfully!")
                self.refresh_password_list()
            else:
                messagebox.showerror("Error", "Failed to delete password!")

    def generate_password_dialog(self):
        """Show password generation dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Generate Password")
        dialog.geometry("400x300")
        dialog.configure(bg='#34495e')
        dialog.transient(self.root)
        dialog.grab_set()

        tk.Label(dialog, text="Password Length:", bg='#34495e', fg='white').pack(pady=10)
        length_var = tk.IntVar(value=16)
        length_scale = tk.Scale(dialog, from_=8, to=32, orient='horizontal',
                                variable=length_var, bg='#34495e', fg='white')
        length_scale.pack(pady=5)

        include_symbols = tk.BooleanVar(value=True)
        symbols_check = tk.Checkbutton(dialog, text="Include Symbols",
                                       variable=include_symbols, bg='#34495e', fg='white')
        symbols_check.pack(pady=10)

        tk.Label(dialog, text="Generated Password:", bg='#34495e', fg='white').pack(pady=10)
        password_var = tk.StringVar()
        password_display = tk.Entry(dialog, textvariable=password_var, font=('Courier', 12),
                                    width=40, state='readonly')
        password_display.pack(pady=5)

        def generate_new():
            password = self.pm.generate_password(length_var.get(), include_symbols.get())
            password_var.set(password)

        btn_frame = tk.Frame(dialog, bg='#34495e')
        btn_frame.pack(pady=20)

        generate_btn = tk.Button(btn_frame, text="Generate", command=generate_new,
                                 bg='#9b59b6', fg='white', font=('Arial', 12, 'bold'))
        generate_btn.pack(side='left', padx=10)

        copy_btn = tk.Button(btn_frame, text="Copy",
                             command=lambda: pyperclip.copy(password_var.get()) or messagebox.showinfo("Success",
                                                                                                       "Password copied!"),
                             bg='#3498db', fg='white', font=('Arial', 12, 'bold'))
        copy_btn.pack(side='left', padx=10)

        close_btn = tk.Button(btn_frame, text="Close",
                              command=dialog.destroy,
                              bg='#e74c3c', fg='white', font=('Arial', 12, 'bold'))
        close_btn.pack(side='left', padx=10)

        generate_new()


if __name__ == "__main__":
    app = PasswordManagerGUI()
    app.root.mainloop()
