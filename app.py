from flask import Flask, render_template, redirect, url_for, session, request, jsonify
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
import os
import json
from werkzeug.security import generate_password_hash, check_password_hash
import base64
import msal
import requests
from datetime import datetime, timedelta
from dotenv import load_dotenv
import hashlib
from google.auth.transport.requests import Request

import tkinter as tk
from tkinter import filedialog
from flask import jsonify
selected_folder_path = None

import hashlib
GMAIL_CLIENT_SECRETS_FILE = 'gmail_client_secrets.json'
DRIVE_CLIENT_SECRETS_FILE = 'Gdrive_client_secrets.json'

def get_local_file_hash(file_path):
    hasher = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()
    except:
        return None

def calculate_carbon_grams(file_path):
    try:
        size_bytes = os.path.getsize(file_path)
        return round(size_bytes * 2.93e-9 * 12, 4)
    except:
        return 0
def get_last_accessed(file_path):
    try:
        if os.path.exists(file_path):
            atime = os.path.getatime(file_path)
            formatted = datetime.fromtimestamp(atime).strftime('%Y-%m-%d %H:%M:%S')
            print(f"[DEBUG] Last access for {file_path}: {formatted}")
            return formatted
        else:
            print(f"[DEBUG] File doesn't exist: {file_path}")
            return "File does not exist"
    except Exception as e:
        print(f"[ERROR] Cannot get last access time for {file_path}: {e}")
        return "Unavailable"





# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-fixed-secret-key-123')

from datetime import datetime
import joblib

def datetimeformat(value, format='%Y-%m-%d %H:%M:%S'):
    """Format a datetime string or timestamp to a readable format."""
    if isinstance(value, (int, float)):
        dt = datetime.fromtimestamp(value)
    else:
        try:
            dt = datetime.strptime(value, '%Y-%m-%dT%H:%M:%S.%fZ')
        except Exception:
            try:
                dt = datetime.strptime(value, '%Y-%m-%dT%H:%M:%S')
            except Exception:
                return value
    return dt.strftime(format)

app.jinja_env.filters['datetimeformat'] = datetimeformat

# Load the trained email classifier model
email_classifier = joblib.load("email_classifier.pkl")

# Gmail API setup
CLIENT_SECRETS_FILE = 'gmail_client_secrets.json'
GMAIL_SCOPES = ['https://www.googleapis.com/auth/gmail.modify',
                 'https://mail.google.com/',
               ]


# Define all required Google Drive scopes
GOOGLE_SCOPES = [
    'https://www.googleapis.com/auth/drive.metadata.readonly',
    'https://www.googleapis.com/auth/drive.file',
    'https://www.googleapis.com/auth/drive',  # Full access to files and folders
    'https://www.googleapis.com/auth/drive.readonly',
    'https://www.googleapis.com/auth/gmail.modify'
]
GOOGLE_API_KEY = os.getenv('GOOGLE_API_KEY')

# OAuth 2.0 configuration
GOOGLE_REDIRECT_URI = 'http://127.0.0.1:5000/google-callback'  # For Google Drive
REDIRECT_URI = 'http://127.0.0.1:5000/oauth2callback'  # For Gmail

# Initialize Google OAuth flow
def get_google_flow():
    return Flow.from_client_secrets_file(
        DRIVE_CLIENT_SECRETS_FILE,
        scopes=GOOGLE_SCOPES,
        redirect_uri=GOOGLE_REDIRECT_URI
    )

def get_gmail_flow():
    return Flow.from_client_secrets_file(
        GMAIL_CLIENT_SECRETS_FILE,
        scopes=['https://www.googleapis.com/auth/gmail.modify'],
        redirect_uri=REDIRECT_URI
    )


# MySQL Configuration
db_config = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER', 'rooteco'),
    'password': os.getenv('DB_PASSWORD', 'Eco123@#'),
    'database': os.getenv('DB_NAME', 'ecoclean_db'),
    'auth_plugin': os.getenv('DB_AUTH_PLUGIN', 'mysql_native_password')
}

# Initialize MySQL connection
def get_db_connection():
    import mysql.connector
    return mysql.connector.connect(**db_config)

# Create database and tables if they don't exist
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create database if it doesn't exist
    cursor.execute("CREATE DATABASE IF NOT EXISTS ecoclean_db")
    cursor.execute("USE ecoclean_db")
    
    # Create users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    conn.commit()
    cursor.close()
    conn.close()

# Initialize database on startup
init_db()

def get_gmail_service():
    if 'credentials' not in session:
        return None
    try:
        credentials = Credentials(**session['credentials'])
        return build('gmail', 'v1', credentials=credentials)
    except Exception as e:
        print(f"Error creating Gmail service: {str(e)}")
        return None
    subject = email.get('subject', '').lower()
    snippet = email.get('snippet', '').lower()
    text_to_check = subject + ' ' + snippet
    
    if any(word in text_to_check for word in ['sale', 'offer', 'discount', 'promotion']):
        return 'promotional'
    elif any(word in text_to_check for word in ['facebook', 'twitter', 'linkedin']):
        return 'social'
    elif any(word in text_to_check for word in ['urgent', 'important', 'priority']):
        return 'important'
    return 'other'

def calculate_email_carbon(size_bytes):
    # Base calculations for yearly carbon emission
    # Average email storage carbon emission is about 4g CO2 per year
    # Additional factors:
    # - Email size (larger emails = more storage = more carbon)
    # - Server storage and cooling
    # - Data transmission and processing
    
    base_carbon = 4  # grams of CO2 per year
    size_factor = size_bytes / 1024  # Convert to KB
    
    # Calculate yearly carbon emission
    # Base emission + size-based additional emission
    yearly_carbon = base_carbon * (1 + size_factor/1000)
    
    # Add server storage and cooling factor (approximately 20% of base)
    server_factor = yearly_carbon * 0.2
    
    # Add data transmission factor (approximately 10% of base)
    transmission_factor = yearly_carbon * 0.1
    
    total_yearly_carbon = yearly_carbon + server_factor + transmission_factor
    
    return round(total_yearly_carbon, 2)  # grams of CO2 per year

def get_email_content(service, message_id):
    try:
        message = service.users().messages().get(userId='me', id=message_id, format='full').execute()
        
        # Get email body
        if 'payload' in message and 'parts' in message['payload']:
            parts = message['payload']['parts']
            body = ''
            for part in parts:
                if part.get('mimeType') == 'text/plain':
                    if 'data' in part['body']:
                        body += base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
                    elif 'attachmentId' in part['body']:
                        attachment = service.users().messages().attachments().get(
                            userId='me', messageId=message_id, id=part['body']['attachmentId']
                        ).execute()
                        body += base64.urlsafe_b64decode(attachment['data']).decode('utf-8')
        else:
            body = base64.urlsafe_b64decode(message['payload']['body']['data']).decode('utf-8') if 'data' in message['payload']['body'] else ''
        
        return body
    except Exception as e:
        print(f"Error getting email content: {str(e)}")
        return ''

# User authentication routes
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    if not all([username, email, password]):
        return jsonify({'error': 'All fields are required'}), 400
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Check if email already exists
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            return jsonify({'error': 'Email already registered'}), 400
        
        # Hash password and store user
        hashed_password = generate_password_hash(password)
        cursor.execute(
            "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
            (username, email, hashed_password)
        )
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({'message': 'Registration successful'}), 201
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    if not all([email, password]):
        return jsonify({'error': 'Email and password are required'}), 400
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Get user by email
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return jsonify({'message': 'Login successful'}), 200
        else:
            return jsonify({'error': 'Invalid email or password'}), 401
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/')
def index():
    return render_template('firsthome.html')

@app.route('/firsthome')
def firsthome():
    return render_template('firsthome.html')

@app.route('/home')
def home():
    if 'user_id' not in session:
        return redirect(url_for('firsthome'))
    
    # Check if Google Drive is connected
    drive_connected = False
    if 'google_credentials' in session:
        try:
            credentials = Credentials.from_authorized_user_info(session['google_credentials'])
            service = build('drive', 'v3', credentials=credentials)
            service.files().list(pageSize=1).execute()
            drive_connected = True
        except:
            drive_connected = False
    
    return render_template('home.html', 
                         authenticated=True,
                         username=session.get('username'),
                         drive_connected=drive_connected,
                         google_api_key=GOOGLE_API_KEY)

@app.route('/home3')
def home3():
    return render_template('home3.html')

@app.route('/resources')
def resources():
    return render_template('resources.html')

@app.route('/base')
def base():
    return render_template('base.html')

@app.route('/email_inbox')
def email_inbox():
    if 'credentials' not in session:
        return redirect(url_for('authorize'))
    
    service = get_gmail_service()
    if not service:
        return redirect(url_for('authorize'))
    
    try:
        # Get emails and classify using ML model
        results = service.users().messages().list(userId='me', maxResults=50).execute()
        messages = results.get('messages', [])

        emails = []
        session['last_texts'] = {}  # Reset previous email text tracking

        category_counts = {
            'Important': 0,
            'Social': 0,
            'Promotional': 0,
            'Newsletter': 0,
            'Spam': 0,
            'Other': 0
        }

        updated_categories = session.get('updated_categories', {})

        for message in messages:
            msg = service.users().messages().get(userId='me', id=message['id']).execute()
            headers = msg['payload']['headers']

            subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), 'No Subject')
            import re

            raw_sender = next((h['value'] for h in headers if h['name'].lower() == 'from'), 'Unknown')
            match = re.search(r'[\w\.-]+@[\w\.-]+', raw_sender)
            sender = match.group(0) if match else raw_sender


            text = sender + " " + subject + " " + msg.get('snippet', '')


            # Save raw text for feedback (used in adaptive learning)
            session['last_texts'][message['id']] = text

            # Check sender-based preference first
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("SELECT preferred_category FROM preferred_senders WHERE sender = %s", (sender,))
                result = cursor.fetchone()
                cursor.close()
                conn.close()

                if result:
                    category = result[0]  # Use user-defined preference
                else:
                    try:
                        category = email_classifier.predict([text])[0]
                    except Exception:
                        category = 'Other'
            except Exception as e:
                print(f"[ERROR] Fetching sender preference: {e}")
                try:
                    category = email_classifier.predict([text])[0]
                except Exception:
                    category = 'Other'

            # Override category if updated by user (session-based)
            if message['id'] in updated_categories:
                category = updated_categories[message['id']]


            if category not in category_counts:
                category = 'Other'
            category_counts[category] += 1

            size_bytes = int(msg.get('sizeEstimate', 0))
            co2_emission = 4 + (size_bytes / 1024) * 0.1  # Example CO2 calculation

            email_data = {
                'id': message['id'],
                'subject': subject,
                'from': sender,
                'snippet': msg.get('snippet', ''),
                'category': category,
                'co2_emission': round(co2_emission, 2)
            }
            emails.append(email_data)
        
        total_emails = len(emails)

        # Get the user's email ID
        mail_id = None
        try:
            profile = service.users().getProfile(userId='me').execute()
            mail_id = profile.get('emailAddress')
        except Exception as e:
            print(f"Error getting mail id: {str(e)}")
            mail_id = None

        return render_template(
            'email_inbox.html',
            emails=emails,
            total_emails=total_emails,
            category_counts=category_counts,
            mail_id=mail_id
        )

    except Exception as e:
        print(f"Error in email_inbox: {str(e)}")
        error_message = "Failed to fetch emails. Please try again."
        return render_template(
            'email_inbox.html',
            emails=[],
            total_emails=0,
            category_counts={},
            error=error_message,
            mail_id=None
        )

@app.route('/authorize')
def authorize():
    try:
        flow = get_gmail_flow()  # Use Gmail flow instead of Google flow
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent'
        )
        session['state'] = state
        return redirect(authorization_url)
    except Exception as e:
        print(f"Error in authorize: {str(e)}")
        return f"An error occurred during authorization: {str(e)}", 500

@app.route('/oauth2callback')
def oauth2callback():
    try:
        if 'state' not in session:
            return redirect(url_for('home'))

        flow = get_gmail_flow()  # Use Gmail flow instead of Google flow
        flow.state = session['state']
        
        # Get the authorization code from the request URL
        authorization_response = request.url
        if not authorization_response:
            return "No authorization response received", 400

        # Fetch the access token
        flow.fetch_token(authorization_response=authorization_response)
        
        # Get credentials and store in session
        credentials = flow.credentials
        
        # Update session credentials with new scopes to handle scope changes gracefully
        session['credentials'] = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': list(set(credentials.scopes))  # Ensure unique scopes
        }
        
        return redirect(url_for('email_inbox'))
    except Exception as e:
        print(f"Error in oauth2callback: {str(e)}")
        session.clear()
        return redirect(url_for('email_inbox'))


@app.route('/connect_google_drive')
def connect_google_drive():
    try:
        # Clear any existing credentials
        session.pop('google_credentials', None)
        
        # Generate authorization URL
        flow = get_google_flow()
        auth_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent'  # Force consent screen to ensure refresh token
        )
        
        # Store state in session
        session['state'] = state
        
        return redirect(auth_url)
    except Exception as e:
        print(f"Error in connect_google_drive: {str(e)}")
        return f"Error connecting to Google Drive: {str(e)}", 500

@app.route('/google-callback')
def google_callback():
    try:
        if 'state' not in session:
            return redirect(url_for('home'))
            
        flow = get_google_flow()
        flow.fetch_token(authorization_response=request.url)
        
        credentials = flow.credentials
        session['google_credentials'] = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes
        }
        
        return redirect(url_for('home'))
    except Exception as e:
        print(f"Error in google_callback: {str(e)}")
        return str(e), 500

@app.route('/check_drive_connection')
def check_drive_connection():
    if 'google_credentials' not in session:
        return jsonify({'connected': False, 'message': 'Not connected to Google Drive'})

    try:
        credentials = Credentials.from_authorized_user_info(session['google_credentials'])
        service = build('drive', 'v3', credentials=credentials)
        service.files().list(pageSize=1).execute()
        return jsonify({'connected': True, 'message': 'Connected to Google Drive'})
    except Exception as e:
        print(f"Error checking Google Drive connection: {str(e)}")
        return jsonify({'connected': False, 'message': str(e)})

@app.route('/list_drive_files')
def list_drive_files():
    if 'google_credentials' not in session:
        return redirect(url_for('connect_google_drive'))
    
    try:
        credentials = Credentials.from_authorized_user_info(session['google_credentials'])
        service = build('drive', 'v3', credentials=credentials)
        
        # Get files from Google Drive
        results = service.files().list(
            pageSize=10,
            fields="nextPageToken, files(id, name, mimeType, webViewLink)"
        ).execute()
        
        files = results.get('files', [])
        return render_template('files.html', files=files)
            
    except Exception as e:
        print(f"Error listing files: {str(e)}")
        return str(e), 500

@app.route('/get_file/<file_id>')
def get_file(file_id):
    if 'google_credentials' not in session:
        return redirect(url_for('connect_google_drive'))
    
    try:
        credentials = Credentials.from_authorized_user_info(session['google_credentials'])
        service = build('drive', 'v3', credentials=credentials)
        
        # Get file metadata
        file = service.files().get(
            fileId=file_id,
            fields='webViewLink'
        ).execute()
        
        if file.get('webViewLink'):
            return redirect(file['webViewLink'])
        else:
            return "No view link available", 400
            
    except Exception as e:
        print(f"Error getting file: {str(e)}")
        return str(e), 500

@app.route('/browse_folder/<folder_id>')
def browse_folder(folder_id):
    if 'google_credentials' not in session:
        return redirect(url_for('connect_google_drive'))
    
    try:
        credentials = Credentials.from_authorized_user_info(session['google_credentials'])
        service = build('drive', 'v3', credentials=credentials)
        
        # Get folder contents
        results = service.files().list(
            q=f"'{folder_id}' in parents",
            fields="nextPageToken, files(id, name, mimeType, webViewLink)"
        ).execute()
        
        files = results.get('files', [])
        return render_template('files.html', files=files, current_folder_id=folder_id)
            
    except Exception as e:
        print(f"Error browsing folder: {str(e)}")
        return str(e), 500

@app.route('/disconnect_drive', methods=['POST'])
def disconnect_drive():
    if 'google_credentials' in session:
        session.pop('google_credentials')
    return jsonify({'success': True})

@app.route('/disconnect_mail', methods=['GET','POST'])
def disconnect_mail():
    if 'credentials' in session:
        session.pop('credentials')
    return jsonify({'success': True})

@app.route('/get_drive_token')
def get_drive_token():
    if 'google_credentials' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        credentials = Credentials.from_authorized_user_info(session['google_credentials'])
        if credentials and credentials.valid:
            return jsonify({'token': credentials.token})
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
    except Exception as e:
        print(f"Error getting drive token: {str(e)}")
        return jsonify({'error': str(e)}), 500

def calculate_file_carbon(size_bytes):
    # Base calculations for yearly carbon emission
    # Average file storage carbon emission is about 10g CO2 per year per MB
    # Additional factors:
    # - File size (larger files = more storage = more carbon)
    # - Server storage and cooling
    # - Data transmission and processing
    
    size_mb = size_bytes / (1024 * 1024)  # Convert to MB
    base_carbon = 10  # grams of CO2 per year per MB
    
    # Calculate yearly carbon emission
    yearly_carbon = base_carbon * size_mb
    
    # Add server storage and cooling factor (approximately 20% of base)
    server_factor = yearly_carbon * 0.2
    
    # Add data transmission factor (approximately 10% of base)
    transmission_factor = yearly_carbon * 0.1
    
    total_yearly_carbon = yearly_carbon + server_factor + transmission_factor
    
    return round(total_yearly_carbon, 2)  # grams of CO2 per year

def get_file_content_hash(service, file_id):
    try:
        # Get file content
        request = service.files().get_media(fileId=file_id)
        content = request.execute()
        
        # Calculate MD5 hash of content
        return hashlib.md5(content).hexdigest()
    except Exception as e:
        print(f"Error getting file content: {str(e)}")
        return None

def group_files_by_content(service, files):
    # First group by size (quick check)
    size_groups = {}
    for file in files:
        if file.get('size'):
            size = file['size']
            if size not in size_groups:
                size_groups[size] = []
            size_groups[size].append(file)
    
    # Then group by content hash for files with same size
    content_groups = {}
    for size, group in size_groups.items():
        if len(group) > 1:  # Only check files with same size
            for file in group:
                content_hash = get_file_content_hash(service, file['id'])
                if content_hash:
                    key = f"{content_hash}_{size}"
                    if key not in content_groups:
                        content_groups[key] = []
                    content_groups[key].append(file)
    
    return content_groups

def get_file_hash(service, file_id, file_name):
    """Get a hash for the file using metadata or content"""
    try:
        # First try to get the MD5 checksum
        file = service.files().get(fileId=file_id, fields='md5Checksum,mimeType').execute()
        
        # If we have MD5 checksum, use it
        if 'md5Checksum' in file:
            return file['md5Checksum']
        
        # For Google Docs and other Google native files, use name and modified time
        if file['mimeType'].startswith('application/vnd.google-apps'):
            return file_name
            
        # For other files without checksum, try to get content hash
        try:
            request = service.files().get_media(fileId=file_id)
            content = request.execute()
            return hashlib.md5(content).hexdigest()
        except:
            # If we can't get content, use filename as fallback
            return file_name
    except Exception as e:
        print(f"Error getting file hash: {str(e)}")
        return file_name

@app.route('/scan_duplicates')
def scan_duplicates():
    if 'google_credentials' not in session:
        return jsonify({'error': 'Not connected to Google Drive'}), 401
    
    try:
        credentials = Credentials.from_authorized_user_info(session['google_credentials'])
        service = build('drive', 'v3', credentials=credentials)
        
        print("Starting duplicate scan...")  # Debug log
        
        # Get all files from Google Drive
        results = service.files().list(
            pageSize=1000,
            fields="nextPageToken, files(id, name, size, mimeType, createdTime, modifiedTime, md5Checksum)",
            q="trashed = false and mimeType != 'application/vnd.google-apps.folder'"  # Exclude folders and trashed files
        ).execute()
        
        files = results.get('files', [])
        print(f"Found {len(files)} files")  # Debug log
        
        # Group files by size first (quick filter)
        size_groups = {}
        for file in files:
            if file.get('size'):
                size = int(file['size'])
                if size not in size_groups:
                    size_groups[size] = []
                size_groups[size].append(file)
        
        # Then check for duplicates within same-size groups
        duplicate_groups = []
        total_co2 = 0
        duplicate_co2 = 0
        
        for size, size_group in size_groups.items():
            if len(size_group) > 1:  # Only check groups with potential duplicates
                # Group by hash
                hash_groups = {}
                for file in size_group:
                    file_hash = get_file_hash(service, file['id'], file['name'])
                    if file_hash not in hash_groups:
                        hash_groups[file_hash] = []
                    hash_groups[file_hash].append(file)
                
                # Add groups with duplicates
                for hash_group in hash_groups.values():
                    if len(hash_group) > 1:
                        # Sort by creation time to determine original
                        hash_group.sort(key=lambda x: x['createdTime'])
                        
                        original = hash_group[0]
                        original_co2 = calculate_file_carbon(int(original['size']))
                        total_co2 += original_co2
                        
                        duplicates = []
                        for dup in hash_group[1:]:
                            dup_co2 = calculate_file_carbon(int(dup['size']))
                            duplicate_co2 += dup_co2
                            duplicates.append({
                                'id': dup['id'],
                                'name': dup['name'],
                                'size': int(dup['size']),
                                'createdTime': dup['createdTime'],
                                'modifiedTime': dup['modifiedTime'],
                                'co2_emission': dup_co2
                            })
                        
                        if duplicates:  # Only add groups that actually have duplicates
                            duplicate_groups.append({
                                'original': {
                                    'id': original['id'],
                                    'name': original['name'],
                                    'size': int(original['size']),
                                    'createdTime': original['createdTime'],
                                    'modifiedTime': original['modifiedTime'],
                                    'co2_emission': original_co2
                                },
                                'duplicates': duplicates,
                                'total_duplicate_co2': sum(d['co2_emission'] for d in duplicates)
                            })
        
        print(f"Found {len(duplicate_groups)} duplicate groups")  # Debug log
        
        return jsonify({
            'total_co2': total_co2,
            'duplicate_co2': duplicate_co2,
            'duplicate_groups': duplicate_groups,
            'total_files': len(files),
            'duplicate_groups_count': len(duplicate_groups)
        })
        
    except Exception as e:
        print(f"Error in scan_duplicates: {str(e)}")  # Debug log
        return jsonify({'error': str(e)}), 500

@app.route('/delete_duplicate/<file_id>', methods=['POST'])
def delete_duplicate(file_id):
    if 'google_credentials' not in session:
        return jsonify({'error': 'Not connected to Google Drive'}), 401
    
    try:
        credentials = Credentials.from_authorized_user_info(session['google_credentials'])
        service = build('drive', 'v3', credentials=credentials)
        
        try:
            # First verify we have access to the file
            file = service.files().get(fileId=file_id, fields='name,size,trashed').execute()
            
            if file.get('trashed', False):
                return jsonify({'error': 'File is already in trash'}), 400
            
            # Try to trash the file instead of permanent deletion
            service.files().update(fileId=file_id, body={'trashed': True}).execute()
            
            return jsonify({
                'message': 'File moved to trash successfully',
                'name': file.get('name', 'Unknown file'),
                'size': file.get('size', '0')
            })
            
        except Exception as e:
            if 'File not found' in str(e):
                return jsonify({'error': 'File not found or already deleted'}), 404
            return jsonify({'error': f'Error deleting file: {str(e)}'}), 403
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/delete_file/<file_id>', methods=['POST'])
def delete_file(file_id):
    if 'google_credentials' not in session:
        return jsonify({'error': 'Not connected to Google Drive'}), 401
    
    try:
        credentials = Credentials.from_authorized_user_info(session['google_credentials'])
        
        # Check if credentials are expired and refresh if needed
        if credentials.expired:
            try:
                credentials.refresh(Request())
                # Update the session with new credentials
                session['google_credentials'] = {
                    'token': credentials.token,
                    'refresh_token': credentials.refresh_token,
                    'token_uri': credentials.token_uri,
                    'client_id': credentials.client_id,
                    'client_secret': credentials.client_secret,
                    'scopes': credentials.scopes
                }
            except Exception as e:
                return jsonify({'error': 'Session expired. Please reconnect to Google Drive'}), 401
        
        service = build('drive', 'v3', credentials=credentials)
        
        try:
            # Get file metadata and current permissions
            file = service.files().get(
                fileId=file_id,
                fields='*'  # Get all file metadata
            ).execute()
            
            if file.get('trashed', False):
                return jsonify({'error': 'File is already in trash'}), 400
            
            # Get current user's email
            me = service.about().get(fields='user').execute()
            current_user = me.get('user', {}).get('emailAddress')
            
            # Get existing permissions
            permissions = service.permissions().list(
                fileId=file_id,
                fields='permissions(id,emailAddress,role,type)'
            ).execute().get('permissions', [])
            
            # Remove all existing permissions except owner
            for permission in permissions:
                if permission.get('role') != 'owner':
                    try:
                        service.permissions().delete(
                            fileId=file_id,
                            permissionId=permission['id']
                        ).execute()
                    except Exception as e:
                        print(f"Error removing permission: {str(e)}")
            
            # Try to add full access permission for current user
            try:
                service.permissions().create(
                    fileId=file_id,
                    body={
                        'role': 'owner',
                        'type': 'user',
                        'emailAddress': current_user
                    },
                    transferOwnership=True,
                    supportsAllDrives=True
                ).execute()
            except Exception as e:
                print(f"Error updating permissions: {str(e)}")
                # Try with writer role if owner transfer fails
                try:
                    service.permissions().create(
                        fileId=file_id,
                        body={
                            'role': 'writer',
                            'type': 'user',
                            'emailAddress': current_user
                        }
                    ).execute()
                except Exception as e:
                    print(f"Error adding writer permission: {str(e)}")
            
            # Try multiple deletion methods
            deletion_methods = [
                # Method 1: Direct delete
                lambda: service.files().delete(fileId=file_id).execute(),
                # Method 2: Move to trash
                lambda: service.files().update(fileId=file_id, body={'trashed': True}).execute(),
                # Method 3: Remove from all folders and then delete
                lambda: (
                    service.files().update(
                        fileId=file_id,
                        removeParents=','.join([p for p in file.get('parents', [])]),
                        fields='id'
                    ).execute(),
                    service.files().delete(fileId=file_id).execute()
                )
            ]
            
            last_error = None
            for method in deletion_methods:
                try:
                    method()
                    return jsonify({
                        'message': 'File deleted successfully',
                        'name': file.get('name', 'Unknown file'),
                        'size': str(file.get('size', '0'))
                    })
                except Exception as e:
                    last_error = e
                    print(f"Deletion method failed: {str(e)}")
                    continue
            
            # If all methods failed, raise the last error
            if last_error:
                raise last_error
            
        except Exception as e:
            error_message = str(e)
            if 'File not found' in error_message:
                return jsonify({'error': 'File not found or already deleted'}), 404
            elif 'insufficientPermissions' in error_message or 'insufficient permissions' in error_message.lower():
                return jsonify({'error': 'Cannot delete file. Please try disconnecting and reconnecting to Google Drive.'}), 403
            elif 'rateLimitExceeded' in error_message:
                return jsonify({'error': 'Rate limit exceeded. Please try again later'}), 429
            else:
                print(f"Error details: {error_message}")
                return jsonify({'error': f'Error deleting file: {error_message}'}), 500
            
    except Exception as e:
        print(f"Error in delete_file: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/analyze_files')
def analyze_files():
    if 'google_credentials' not in session:
        return jsonify({'error': 'Not connected to Google Drive'}), 401
    
    try:
        credentials = Credentials.from_authorized_user_info(session['google_credentials'])
        service = build('drive', 'v3', credentials=credentials)
        
        # Get all files from Google Drive with detailed information
        results = service.files().list(
            pageSize=1000,
            fields="nextPageToken, files(id, name, size, mimeType, createdTime, modifiedTime, lastModifyingUser, viewedByMeTime, viewedByMe)",
            q="trashed = false and mimeType != 'application/vnd.google-apps.folder'"  # Exclude folders and trashed files
        ).execute()
        
        files = results.get('files', [])
        total_co2 = 0
        total_size = 0
        analyzed_files = []
        file_type_stats = {}
        
        # Process each file
        for file in files:
            if file.get('size'):
                size = int(file.get('size', 0))
                total_size += size
                co2 = calculate_file_carbon(size)
                total_co2 += co2
                
                # Get file type
                mime_type = file.get('mimeType', 'unknown')
                file_type = get_friendly_file_type(mime_type)
                
                # Update file type statistics
                if file_type not in file_type_stats:
                    file_type_stats[file_type] = {
                        'count': 0,
                        'total_size': 0,
                        'co2': 0
                    }
                file_type_stats[file_type]['count'] += 1
                file_type_stats[file_type]['total_size'] += size
                file_type_stats[file_type]['co2'] += co2
                
                # Calculate access frequency and last access
                last_accessed = file.get('viewedByMeTime', file.get('modifiedTime', file['createdTime']))
                days_since_access = (datetime.now() - datetime.strptime(last_accessed.split('.')[0], '%Y-%m-%dT%H:%M:%S')).days
                
                analyzed_files.append({
                    'id': file['id'],
                    'name': file['name'],
                    'size': size,
                    'type': file_type,
                    'co2_emission': co2,
                    'lastAccessed': last_accessed,
                    'daysSinceAccess': days_since_access,
                    'accessCount': 1 if file.get('viewedByMe') else 0
                })
        
        # Sort files by CO2 emission (descending)
        analyzed_files.sort(key=lambda x: (-x['co2_emission'], x['daysSinceAccess']))
        
        # Calculate potential CO2 reduction (sum of CO2 from least accessed files)
        potential_reduction = sum(f['co2_emission'] for f in analyzed_files 
                                if f['daysSinceAccess'] > 180)  # Files not accessed in 6 months
        
        # Generate storage timeline data (last 6 months)
        timeline_data = generate_storage_timeline(files)
        
        return jsonify({
            'total_files': len(files),
            'total_size': total_size,
            'total_co2': total_co2,
            'potential_reduction': potential_reduction,
            'files': analyzed_files,
            'file_type_stats': file_type_stats,
            'storage_timeline': timeline_data
        })
        
    except Exception as e:
        print(f"Error in analyze_files: {str(e)}")
        return jsonify({'error': str(e)}), 500

def get_friendly_file_type(mime_type):
    """Convert MIME type to user-friendly file type name"""
    type_map = {
        'application/pdf': 'PDF Documents',
        'application/msword': 'Word Documents',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'Word Documents',
        'application/vnd.ms-excel': 'Excel Spreadsheets',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'Excel Spreadsheets',
        'image/jpeg': 'Images',
        'image/png': 'Images',
        'image/gif': 'Images',
        'video/mp4': 'Videos',
        'video/quicktime': 'Videos',
        'application/zip': 'Archives',
        'application/x-zip-compressed': 'Archives',
        'application/vnd.google-apps.document': 'Google Docs',
        'application/vnd.google-apps.spreadsheet': 'Google Sheets',
        'application/vnd.google-apps.presentation': 'Google Slides'
    }
    return type_map.get(mime_type, 'Other Files')

def generate_storage_timeline(files):
    """Generate storage usage timeline data for the last 6 months"""
    end_date = datetime.now()
    start_date = end_date - timedelta(days=180)
    
    # Create monthly buckets
    months = {}
    current = start_date
    while current <= end_date:
        months[current.strftime('%Y-%m')] = 0
        current += timedelta(days=30)
    
    # Aggregate file sizes by month
    for file in files:
        if file.get('size'):
            created_date = datetime.strptime(file['createdTime'].split('T')[0], '%Y-%m-%d')
            if created_date >= start_date:
                month_key = created_date.strftime('%Y-%m')
                if month_key in months:
                    months[month_key] += int(file['size'])
    
    # Convert to GB and prepare timeline data
    labels = list(months.keys())
    data = [round(size / (1024 * 1024 * 1024), 2) for size in months.values()]  # Convert to GB
    
    return {
        'labels': labels,
        'data': data
    }

@app.route('/get_email_content/<email_id>')
def get_email_content(email_id):
    if 'credentials' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    service = get_gmail_service()
    if not service:
        return jsonify({'success': False, 'error': 'Gmail service not available'}), 500
    
    try:
        # Get the full email content
        message = service.users().messages().get(
            userId='me',
            id=email_id,
            format='full'
        ).execute()
        
        # Extract email body
        content = ''
        if 'payload' in message:
            if 'parts' in message['payload']:
                for part in message['payload']['parts']:
                    if part.get('mimeType') == 'text/plain':
                        if 'data' in part['body']:
                            content += base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
                        elif 'attachmentId' in part['body']:
                            attachment = service.users().messages().attachments().get(
                                userId='me',
                                messageId=email_id,
                                id=part['body']['attachmentId']
                            ).execute()
                            content += base64.urlsafe_b64decode(attachment['data']).decode('utf-8')
            elif 'body' in message['payload'] and 'data' in message['payload']['body']:
                content = base64.urlsafe_b64decode(message['payload']['body']['data']).decode('utf-8')
        
        return jsonify({
            'success': True,
            'content': content or 'No content available'
        })
        
    except Exception as e:
        print(f"Error getting email content: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/smart_cleanup', methods=['POST'])
def smart_cleanup():
    if 'credentials' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401

    service = get_gmail_service()
    if not service:
        return jsonify({'success': False, 'error': 'Gmail service not available'}), 500

    try:
        # Re-classify emails and auto-select spam for deletion
        results = service.users().messages().list(userId='me', maxResults=1000).execute()
        messages = results.get('messages', [])
        spam_ids = []
        for message in messages:
            msg = service.users().messages().get(userId='me', id=message['id'], format='full').execute()
            subject = ''
            snippet = msg.get('snippet', '')

            for header in msg['payload'].get('headers', []):
                if header['name'].lower() == 'subject':
                    subject = header['value']

            text = subject + " " + snippet
            try:
                prediction = email_classifier.predict([text])[0]
            except Exception:
                prediction = 'Other'

            if prediction.lower() == 'spam':
                spam_ids.append(message['id'])

        return jsonify({'success': True, 'spam_ids': spam_ids, 'spam_count': len(spam_ids)})

    except Exception as e:
        print(f"Smart Cleanup Error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/mark_important', methods=['POST'])
def mark_important():
    if 'credentials' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401

    email_id = request.json.get('email_id')
    important = request.json.get('important', False)

    if 'important_emails' not in session:
        session['important_emails'] = []

    important_emails = session['important_emails']

    if important:
        if email_id not in important_emails:
            important_emails.append(email_id)
    else:
        if email_id in important_emails:
            important_emails.remove(email_id)

    session['important_emails'] = important_emails
    session.modified = True

    return jsonify({'success': True, 'important_emails': important_emails})

@app.route('/update_category', methods=['POST'])
def update_category():
    if 'credentials' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401

    data = request.get_json()
    email_id = data.get('email_id')
    new_category = data.get('new_category')

    if not email_id or not new_category:
        return jsonify({'success': False, 'error': 'Missing email_id or new_category'}), 400

    # Store in session
    updated_categories = session.get('updated_categories', {})
    updated_categories[email_id] = new_category
    session['updated_categories'] = updated_categories
    session.modified = True
        # Save user preference for sender
        # Save user preference for sender
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        service = get_gmail_service()
        msg = service.users().messages().get(userId='me', id=email_id).execute()
        headers = msg['payload']['headers']

        import re
        raw_sender = next((h['value'] for h in headers if h['name'].lower() == 'from'), None)
        match = re.search(r'[\w\.-]+@[\w\.-]+', raw_sender)
        cleaned_sender = match.group(0) if match else raw_sender

        if cleaned_sender:
            cursor.execute("""
                INSERT INTO preferred_senders (sender, preferred_category)
                VALUES (%s, %s)
                ON DUPLICATE KEY UPDATE preferred_category = VALUES(preferred_category)
            """, (cleaned_sender, new_category))
            conn.commit()
        
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"[ERROR] Failed to store sender preference: {e}")


    # Get text to log (subject + snippet) from session
    email_texts = session.get('last_texts', {})
    email_text = email_texts.get(email_id, "")

    # Insert feedback into database
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS email_feedback (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email_id VARCHAR(255),
                text TEXT,
                updated_category VARCHAR(50),
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            INSERT INTO email_feedback (email_id, text, updated_category)
            VALUES (%s, %s, %s)
        """, (email_id, email_text, new_category))
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Error saving feedback: {e}")  # Don't crash route on failure

    return jsonify({'success': True, 'email_id': email_id, 'new_category': new_category})


@app.route('/delete_email/<email_id>', methods=['POST'])
def delete_email(email_id):
    if 'credentials' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    service = get_gmail_service()
    if not service:
        return jsonify({'error': 'Service not available'}), 500
    
    try:
        # Get email details before deletion to calculate carbon reduction
        msg = service.users().messages().get(userId='me', id=email_id).execute()
        size = int(msg.get('sizeEstimate', 0))
        carbon_reduction = calculate_email_carbon(size)
        
        # Delete the email
        service.users().messages().trash(userId='me', id=email_id).execute()
        
        return jsonify({
            'success': True,
            'carbon_reduction': carbon_reduction
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@app.route('/delete_emails', methods=['POST'])
def delete_emails():
    if 'credentials' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    service = get_gmail_service()
    if not service:
        return jsonify({'error': 'Service not available'}), 500

    try:
        data = request.get_json()
        email_ids = data.get('email_ids', [])

        if not email_ids:
            return jsonify({'error': 'No email IDs provided'}), 400

        deleted = []
        failed = []

        for email_id in email_ids:
            try:
                msg = service.users().messages().get(userId='me', id=email_id).execute()
                size = int(msg.get('sizeEstimate', 0))
                carbon_reduction = calculate_email_carbon(size)

                service.users().messages().trash(userId='me', id=email_id).execute()
                deleted.append({
                    'email_id': email_id,
                    'carbon_reduction': carbon_reduction
                })
            except Exception as e:
                failed.append({'email_id': email_id, 'error': str(e)})

        return jsonify({
            'success': True,
            'deleted': deleted,
            'failed': failed
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

import csv
import re

@app.route('/export_email_dataset')
def export_email_dataset():
    if 'credentials' not in session:
        return "Not authenticated", 401

    service = get_gmail_service()
    if not service:
        return "Gmail service not available", 500

    try:
        results = service.users().messages().list(userId='me', maxResults=200).execute()
        messages = results.get('messages', [])

        dataset_rows = []

        for message in messages:
            msg = service.users().messages().get(userId='me', id=message['id']).execute()
            headers = msg['payload']['headers']

            subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), 'No Subject')
            sender = next((h['value'] for h in headers if h['name'].lower() == 'from'), 'unknown')
            snippet = msg.get('snippet', '')

            clean_sender = re.sub(r'[<>]', '', sender).strip()
            full_text = clean_sender + " " + subject + " " + snippet

            # 🔥 Auto-mark emails from "admin" as Important
            if "admin" in clean_sender.lower():
                label = "Important"
            else:
                # Predict with current model (optional fallback)
                try:
                    label = email_classifier.predict([full_text])[0]
                except:
                    label = "Other"

            dataset_rows.append([clean_sender, subject, snippet, label])

        # Save to CSV
        with open("email_dataset.csv", "w", newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["from", "subject", "body", "label"])
            writer.writerows(dataset_rows)

        return "✅ Exported emails to email_dataset.csv with admin detection!"

    except Exception as e:
        return f"Error exporting dataset: {str(e)}", 500
    
    


@app.route('/browse', methods=['GET'])
def browse():
    global selected_folder_path
    root = tk.Tk()
    root.withdraw()
    folder_selected = filedialog.askdirectory()
    
    if not folder_selected:
        return jsonify({"message": "No folder selected."})

    selected_folder_path = folder_selected
    files = os.listdir(folder_selected)
    return jsonify({
        'folder': folder_selected,
        'files': files
    })



@app.route('/browse_analyze', methods=['GET'])
def browse_analyze():
    global selected_folder_path

    if not selected_folder_path or not os.path.exists(selected_folder_path):
        return jsonify({"error": "No folder selected."}), 400

    hash_map = {}
    file_list = []

    for root, dirs, files in os.walk(selected_folder_path):
        for fname in files:
            fpath = os.path.join(root, fname)
            file_hash = get_local_file_hash(fpath)
            carbon = calculate_carbon_grams(fpath)
            size = os.path.getsize(fpath)
            last_access = get_last_accessed(fpath)
            file_obj = {
                "name": fname,
                "path": fpath,
                "carbon": carbon,
                "size": size,
                "hash": file_hash,
                "last_access": last_access
            }

            file_list.append(file_obj)

            if file_hash:
                hash_map.setdefault(file_hash, []).append(file_obj)

    duplicate_groups = []
    top_emitters = sorted(file_list, key=lambda x: x['carbon'], reverse=True)[:10]

    total_files = len(file_list)
    duplicate_carbon = 0
    duplicate_file_count = 0

    for h, group in hash_map.items():
        if len(group) > 1:
            original = group[0]
            dups = group[1:]

            duplicate_carbon += sum([f['carbon'] for f in dups])
            duplicate_file_count += len(dups)

            duplicate_groups.append({
                "hash": h,
                "original": original,
                "duplicates": dups
            })

    return jsonify({
        "total_files": total_files,
        "duplicate_groups": len(duplicate_groups),
        "scanTotalCO2": round(sum([f['carbon'] for f in file_list]), 4),
        "duplicateCO2": round(duplicate_carbon, 4),
        "duplicateFiles": duplicate_groups,
        "topEmitters": top_emitters
    })




from flask import request, jsonify
import os

@app.route('/delete_local_file', methods=['POST'])
def delete_local_file():
    data = request.get_json()
    file_path = data.get("path")

    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            return jsonify({"success": True})
        else:
            return jsonify({"success": False, "error": "File not found."}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

import subprocess

@app.route('/retrain_model')
def retrain_model_route():
    try:
        result = subprocess.run(
            ['python', 'retrain_model.py'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if result.returncode == 0:
            return f"<pre>✅ Retrain complete:\n{result.stdout}</pre>"
        else:
            return f"<pre>❌ Retrain failed:\n{result.stderr}</pre>"
    except Exception as e:
        return f"❌ Error running retrain_model.py: {str(e)}"
    
def create_preferred_senders_table():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS preferred_senders (
                sender VARCHAR(255) PRIMARY KEY,
                preferred_category VARCHAR(50)
            );
        """)
        conn.commit()
        cursor.close()
        conn.close()
        print("[INFO] Table 'preferred_senders' ensured in database.")
    except Exception as e:
        print(f"[ERROR] Failed to create preferred_senders table: {e}")


if __name__ == '__main__':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    create_preferred_senders_table()
    app.run(host='127.0.0.1', port=5000, debug=True)
 
