from flask import Flask, request, render_template, redirect, url_for, flash, session
import sqlite3
import hashlib
import secrets
import string
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload
import io
import json
import pyperclip

app = Flask(__name__)
app.secret_key = os.urandom(24)

class PasswordManager:
    def __init__(self):
        self.master_key = None
        self.cipher_suite = None
        self.db_file = "passwords.db"
        self.download_db_from_drive()
        self.setup_database()
        self.upload_db_to_drive()

    def setup_database(self):
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
            self.upload_db_to_drive()
            return True
        except Exception as e:
            print(f"Error setting master password: {e}")
            return False
        finally:
            conn.close()

    def verify_master_password(self, password):
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
        return self.cipher_suite.encrypt(password.encode()).decode()

    def decrypt_password(self, encrypted_password):
        try:
            return self.cipher_suite.decrypt(encrypted_password.encode()).decode()
        except Exception as e:
            print(f"Decryption error: {e}")
            return "DECRYPTION ERROR"

    def add_password(self, site_name, username, password, notes=""):
        try:
            encrypted_password = self.encrypt_password(password)
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO passwords (site_name, username, password, notes)
                VALUES (?, ?, ?, ?)
            ''', (site_name, username, encrypted_password, notes))
            conn.commit()
            self.upload_db_to_drive()
            return True
        except Exception as e:
            print(f"Error adding password: {e}")
            return False
        finally:
            conn.close()

    def get_all_passwords(self):
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
        try:
            encrypted_password = self.encrypt_password(password)
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE passwords SET site_name=?, username=?, password=?, notes=?
                WHERE id=?
            ''', (site_name, username, encrypted_password, notes, password_id))
            conn.commit()
            self.upload_db_to_drive()
            return True
        except Exception as e:
            print(f"Error updating password: {e}")
            return False
        finally:
            conn.close()

    def delete_password(self, password_id):
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM passwords WHERE id=?', (password_id,))
            conn.commit()
            self.upload_db_to_drive()
            return True
        except Exception as e:
            print(f"Error deleting password: {e}")
            return False
        finally:
            conn.close()

    def generate_password(self, length=16, include_symbols=True):
        characters = string.ascii_letters + string.digits
        if include_symbols:
            characters += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        return ''.join(secrets.choice(characters) for _ in range(length))

    def authenticate_drive(self):
        SCOPES = ["https://www.googleapis.com/auth/drive"]
        creds = None
        if os.environ.get("GOOGLE_CREDENTIALS"):
            creds_dict = json.loads(os.environ["GOOGLE_CREDENTIALS"])
            creds = Credentials.from_authorized_user_info(creds_dict, SCOPES)
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_config(
                    json.loads(os.environ["GOOGLE_CLIENT_CONFIG"]), SCOPES
                )
                creds = flow.run_local_server(port=0)
                os.environ["GOOGLE_CREDENTIALS"] = json.dumps({
                    "token": creds.token,
                    "refresh_token": creds.refresh_token,
                    "token_uri": creds.token_uri,
                    "client_id": creds.client_id,
                    "client_secret": creds.client_secret,
                    "scopes": creds.scopes
                })
        self.drive_service = build("drive", "v3", credentials=creds)

    def upload_db_to_drive(self, folder_id="1cDIcBqdG3sXc0sD3ueaKoQI3AGZPtUdr"):
        try:
            if not hasattr(self, "drive_service"):
                self.authenticate_drive()
            file_metadata = {"name": "passwords.db", "parents": [folder_id]}
            media = MediaFileUpload(self.db_file, mimetype="application/x-sqlite3")
            existing_files = self.drive_service.files().list(
                q=f"name='passwords.db' and '{folder_id}' in parents",
                fields="files(id, name)"
            ).execute().get("files", [])
            if existing_files:
                file_id = existing_files[0]["id"]
                self.drive_service.files().update(fileId=file_id, media_body=media).execute()
            else:
                self.drive_service.files().create(body=file_metadata, media_body=media, fields="id").execute()
        except Exception as e:
            print(f"Error uploading database to Drive: {e}")

    def download_db_from_drive(self, folder_id="1cDIcBqdG3sXc0sD3ueaKoQI3AGZPtUdr"):
        try:
            if not hasattr(self, "drive_service"):
                self.authenticate_drive()
            files = self.drive_service.files().list(
                q=f"name='passwords.db' and '{folder_id}' in parents",
                fields="files(id, name)"
            ).execute().get("files", [])
            if not files:
                print("No passwords.db found in Drive folder")
                return
            file_id = files[0]["id"]
            request = self.drive_service.files().get_media(fileId=file_id)
            with open(self.db_file, "wb") as f:
                downloader = MediaIoBaseDownload(f, request)
                done = False
                while not done:
                    status, done = downloader.next_chunk()
        except Exception as e:
            print(f"Error downloading database from Drive: {e}")

pm = PasswordManager()

@app.route('/')
def index():
    if not pm.has_master_password():
        return redirect(url_for('setup'))
    if 'authenticated' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/setup', methods=['GET', 'POST'])
def setup():
    if pm.has_master_password():
        return redirect(url_for('login'))
    if request.method == 'POST':
        password = request.form['password']
        confirm = request.form['confirm']
        if len(password) < 8:
            flash("Password must be at least 8 characters")
            return redirect(url_for('setup'))
        if password != confirm:
            flash("Passwords do not match")
            return redirect(url_for('setup'))
        if pm.set_master_password(password):
            session['authenticated'] = True
            flash("Master password set successfully")
            return redirect(url_for('dashboard'))
        flash("Failed to set master password")
    return render_template('setup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'authenticated' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        password = request.form['password']
        if pm.verify_master_password(password):
            session['authenticated'] = True
            return redirect(url_for('dashboard'))
        flash("Invalid master password")
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'authenticated' not in session:
        return redirect(url_for('login'))
    passwords = pm.get_all_passwords()
    return render_template('dashboard.html', passwords=passwords)

@app.route('/add', methods=['GET', 'POST'])
def add():
    if 'authenticated' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        site_name = request.form['site_name']
        username = request.form['username']
        password = request.form['password']
        notes = request.form.get('notes', '')
        if not site_name or not username or not password:
            flash("All fields are required")
            return redirect(url_for('add'))
        if pm.add_password(site_name, username, password, notes):
            flash("Password added successfully")
            return redirect(url_for('dashboard'))
        flash("Failed to add password")
    return render_template('add.html')

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit(id):
    if 'authenticated' not in session:
        return redirect(url_for('login'))
    passwords = pm.get_all_passwords()
    password = next((p for p in passwords if p[0] == id), None)
    if not password:
        flash("Password not found")
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        site_name = request.form['site_name']
        username = request.form['username']
        password = request.form['password']
        notes = request.form.get('notes', '')
        if not site_name or not username or not password:
            flash("All fields are required")
            return redirect(url_for('edit', id=id))
        if pm.update_password(id, site_name, username, password, notes):
            flash("Password updated successfully")
            return redirect(url_for('dashboard'))
        flash("Failed to update password")
    return render_template('edit.html', password=password)

@app.route('/delete/<int:id>')
def delete(id):
    if 'authenticated' not in session:
        return redirect(url_for('login'))
    if pm.delete_password(id):
        flash("Password deleted successfully")
    else:
        flash("Failed to delete password")
    return redirect(url_for('dashboard'))

@app.route('/generate', methods=['GET', 'POST'])
def generate():
    if 'authenticated' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        length = int(request.form.get('length', 16))
        include_symbols = 'include_symbols' in request.form
        password = pm.generate_password(length, include_symbols)
        return render_template('generate.html', generated_password=password)
    return render_template('generate.html', generated_password=None)

@app.route('/logout')
def logout():
    session.pop('authenticated', None)
    return redirect(url_for('login'))

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
