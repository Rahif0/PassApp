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
            st.error(f"Database error: {e}")
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
            st.error(f"Error setting master password: {e}")
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
            st.error(f"Error verifying master password: {e}")
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
            st.error(f"Database error: {e}")
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
            st.error(f"Decryption error: {e}")
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
            st.error(f"Error adding password: {e}")
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
            st.error(f"Error getting passwords: {e}")
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
            st.error(f"Error updating password: {e}")
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
            st.error(f"Error deleting password: {e}")
            return False
        finally:
            conn.close()

    def generate_password(self, length=16, include_symbols=True):
        """Generate a secure random password"""
        characters = string.ascii_letters + string.digits
        if include_symbols:
            characters += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        return ''.join(secrets.choice(characters) for _ in range(length))


def main():
    st.set_page_config(page_title="🔐 Secure Password Manager", page_icon="🔐", layout="wide")
    
    # Initialize session state
    if 'pm' not in st.session_state:
        st.session_state.pm = PasswordManager()
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'show_passwords' not in st.session_state:
        st.session_state.show_passwords = {}

    st.title("🔐 Secure Password Manager")

    # Authentication
    if not st.session_state.authenticated:
        if not st.session_state.pm.has_master_password():
            st.header("Setup Master Password")
            st.warning("⚠️ Please create a master password to secure your data")
            
            with st.form("setup_form"):
                master_password = st.text_input("Master Password", type="password", help="At least 8 characters")
                confirm_password = st.text_input("Confirm Password", type="password")
                submitted = st.form_submit_button("Create Master Password")
                
                if submitted:
                    if len(master_password) < 8:
                        st.error("Master password must be at least 8 characters long!")
                    elif master_password != confirm_password:
                        st.error("Passwords do not match!")
                    else:
                        if st.session_state.pm.set_master_password(master_password):
                            st.success("Master password created successfully!")
                            st.session_state.authenticated = True
                            st.rerun()
                        else:
                            st.error("Failed to create master password!")
        else:
            st.header("Login")
            with st.form("login_form"):
                master_password = st.text_input("Master Password", type="password")
                submitted = st.form_submit_button("Login")
                
                if submitted:
                    if st.session_state.pm.verify_master_password(master_password):
                        st.session_state.authenticated = True
                        st.rerun()
                    else:
                        st.error("Invalid master password!")
    else:
        # Main application
        col1, col2, col3 = st.columns([1, 1, 1])
        
        with col1:
            if st.button("🚪 Logout"):
                st.session_state.authenticated = False
                st.session_state.show_passwords = {}
                st.rerun()
        
        with col2:
            if st.button("🎲 Generate Password"):
                st.session_state.show_generator = True
        
        with col3:
            if st.button("➕ Add Password"):
                st.session_state.show_add_form = True

        # Password Generator
        if st.session_state.get('show_generator', False):
            st.header("🎲 Password Generator")
            col1, col2 = st.columns(2)
            with col1:
                length = st.slider("Password Length", 8, 32, 16)
            with col2:
                include_symbols = st.checkbox("Include Symbols", value=True)
            
            if st.button("Generate New Password"):
                generated_password = st.session_state.pm.generate_password(length, include_symbols)
                st.code(generated_password, language=None)
                st.success("Password generated! You can copy it from above.")
            
            if st.button("Close Generator"):
                st.session_state.show_generator = False
                st.rerun()

        # Add Password Form
        if st.session_state.get('show_add_form', False):
            st.header("➕ Add New Password")
            with st.form("add_password_form"):
                site_name = st.text_input("Site Name*")
                username = st.text_input("Username*")
                password = st.text_input("Password*", type="password")
                notes = st.text_area("Notes (optional)")
                
                col1, col2 = st.columns(2)
                with col1:
                    submitted = st.form_submit_button("Save Password")
                with col2:
                    cancel = st.form_submit_button("Cancel")
                
                if submitted:
                    if site_name and username and password:
                        if st.session_state.pm.add_password(site_name, username, password, notes):
                            st.success("Password saved successfully!")
                            st.session_state.show_add_form = False
                            st.rerun()
                        else:
                            st.error("Failed to save password!")
                    else:
                        st.error("Please fill in all required fields!")
                
                if cancel:
                    st.session_state.show_add_form = False
                    st.rerun()

        # Search
        st.header("🔍 Your Passwords")
        search_term = st.text_input("Search passwords...", placeholder="Search by site name, username, or notes")

        # Display passwords
        passwords = st.session_state.pm.get_all_passwords()
        
        if passwords:
            # Filter passwords based on search
            if search_term:
                filtered_passwords = []
                for password in passwords:
                    if (search_term.lower() in password[1].lower() or 
                        search_term.lower() in password[2].lower() or 
                        (password[4] and search_term.lower() in password[4].lower())):
                        filtered_passwords.append(password)
                passwords = filtered_passwords

            for password in passwords:
                password_id, site_name, username, decrypted_password, notes, created_date = password
                
                with st.expander(f"🌐 {site_name} - {username}"):
                    col1, col2, col3, col4 = st.columns([2, 2, 1, 1])
                    
                    with col1:
                        st.text(f"Site: {site_name}")
                        st.text(f"Username: {username}")
                    
                    with col2:
                        if st.session_state.show_passwords.get(password_id, False):
                            st.text(f"Password: {decrypted_password}")
                            if st.button("🙈 Hide", key=f"hide_{password_id}"):
                                st.session_state.show_passwords[password_id] = False
                                st.rerun()
                        else:
                            st.text("Password: ************")
                            if st.button("👁️ Show", key=f"show_{password_id}"):
                                st.session_state.show_passwords[password_id] = True
                                st.rerun()
                    
                    with col3:
                        if st.button("📋 Copy", key=f"copy_{password_id}"):
                            # Since we can't access clipboard directly in web apps,
                            # we'll show the password for copying
                            st.session_state.show_passwords[password_id] = True
                            st.success("Password revealed for copying!")
                            st.rerun()
                    
                    with col4:
                        if st.button("🗑️ Delete", key=f"delete_{password_id}"):
                            if st.session_state.pm.delete_password(password_id):
                                st.success("Password deleted!")
                                st.rerun()
                            else:
                                st.error("Failed to delete password!")
                    
                    if notes:
                        st.text(f"Notes: {notes}")
                    
                    if created_date:
                        st.text(f"Created: {created_date[:10]}")
        else:
            st.info("No passwords saved yet. Click 'Add Password' to get started!")


if __name__ == "__main__":
    main()
