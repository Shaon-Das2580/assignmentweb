from flask import Flask, jsonify, request
import pyodbc
from azure.storage.blob import BlobServiceClient, generate_blob_sas, BlobSasPermissions
from dotenv import load_dotenv
import os
import bcrypt
import jwt
import datetime
from functools import wraps

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Secret key for JWT
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_secret_key')

# Azure SQL Connection String from environment variable
SQL_CONNECTION_STRING = os.environ.get("SQL_CONNECTION_STRING")

# Azure Blob Storage Connection String from environment variable
BLOB_CONNECTION_STRING = os.environ.get("BLOB_CONNECTION_STRING")

# Initialize Blob Service Client
blob_service_client = BlobServiceClient.from_connection_string(BLOB_CONNECTION_STRING)

# JWT Token Decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = data['user']
        except Exception as e:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/')
def home():
    return "Backend with Enhanced Features is running!"

# User Signup
@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role', 'consumer')

    if role not in ['creator', 'consumer']:
        return jsonify({'error': 'Invalid role specified!'}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    try:
        conn = pyodbc.connect(SQL_CONNECTION_STRING)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO Users (username, email, password, role) VALUES (?, ?, ?, ?)",
                       (username, email, hashed_password, role))
        conn.commit()
        conn.close()
        return jsonify({'message': 'User registered successfully!'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# User Login
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    try:
        conn = pyodbc.connect(SQL_CONNECTION_STRING)
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password, role FROM Users WHERE email = ?", (email,))
        row = cursor.fetchone()
        conn.close()

        if not row or not bcrypt.checkpw(password.encode('utf-8'), row[2].encode('utf-8')):
            return jsonify({'message': 'Invalid email or password!'}), 401

        token = jwt.encode({'user': {'id': row[0], 'username': row[1], 'role': row[3]},
                            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
                           app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({'token': token}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Upload file to Azure Blob Storage (Creator Only)
@app.route('/upload', methods=['POST'])
@token_required
def upload_file(current_user):
    if current_user['role'] != 'creator':
        return jsonify({'message': 'Unauthorized access!'}), 403

    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']
    blob_name = file.filename

    try:
        # Get the container client
        container_client = blob_service_client.get_container_client("videos")

        # Upload the file
        container_client.upload_blob(blob_name, file, overwrite=True)

        # Save metadata to SQL
        conn = pyodbc.connect(SQL_CONNECTION_STRING)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO Videos (title, filepath, uploaded_by) VALUES (?, ?, ?)",
                       (blob_name, blob_name, current_user['id']))
        conn.commit()
        conn.close()

        return jsonify({'message': f"File '{blob_name}' uploaded successfully!"}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# List all videos with pagination
@app.route('/videos', methods=['GET'])
def list_videos():
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 10))
    offset = (page - 1) * limit

    try:
        conn = pyodbc.connect(SQL_CONNECTION_STRING)
        cursor = conn.cursor()
        cursor.execute("SELECT id, title, filepath, upload_date FROM Videos ORDER BY upload_date DESC OFFSET ? ROWS FETCH NEXT ? ROWS ONLY", (offset, limit))
        rows = cursor.fetchall()
        videos = [{'id': row[0], 'title': row[1], 'filepath': row[2], 'upload_date': row[3]} for row in rows]
        conn.close()
        return jsonify(videos), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Generate pre-signed URL for video playback
@app.route('/videos/<int:video_id>/play', methods=['GET'])
def get_video_url(video_id):
    try:
        conn = pyodbc.connect(SQL_CONNECTION_STRING)
        cursor = conn.cursor()
        cursor.execute("SELECT filepath FROM Videos WHERE id = ?", (video_id,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            return jsonify({'error': 'Video not found!'}), 404

        filepath = row[0]
        sas_token = generate_blob_sas(
            account_name=blob_service_client.account_name,
            container_name="videos",
            blob_name=filepath,
            account_key=blob_service_client.credential.account_key,
            permission=BlobSasPermissions(read=True),
            expiry=datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        )

        url = f"{blob_service_client.primary_endpoint}/videos/{filepath}?{sas_token}"
        return jsonify({'url': url}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Add comments to a video
@app.route('/videos/<int:video_id>/comments', methods=['POST'])
@token_required
def add_comment(current_user, video_id):
    data = request.json
    comment = data.get('comment')

    try:
        conn = pyodbc.connect(SQL_CONNECTION_STRING)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO Comments (video_id, user_id, comment) VALUES (?, ?, ?)",
                       (video_id, current_user['id'], comment))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Comment added successfully!'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/search', methods=['GET'])
def search_videos():
    query = request.args.get('q', '')
    try:
        conn = pyodbc.connect(SQL_CONNECTION_STRING)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, title, description FROM Videos WHERE title LIKE ? OR metadata LIKE ?",
            (f"%{query}%", f"%{query}%")
        )
        rows = cursor.fetchall()
        conn.close()
        results = [{'id': row[0], 'title': row[1], 'description': row[2]} for row in rows]
        return jsonify(results), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/videos/<int:video_id>', methods=['PUT'])
@token_required
def update_video(current_user, video_id):
    if current_user['role'] != 'creator':
        return jsonify({'message': 'Unauthorized access!'}), 403
    data = request.json
    title = data.get('title')
    description = data.get('description')
    try:
        conn = pyodbc.connect(SQL_CONNECTION_STRING)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE Videos SET title = ?, description = ? WHERE id = ? AND uploaded_by = ?",
            (title, description, video_id, current_user['id'])
        )
        conn.commit()
        conn.close()
        return jsonify({'message': 'Video updated successfully!'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/videos/<int:video_id>/rate', methods=['POST'])
@token_required
def rate_video(current_user, video_id):
    data = request.json
    rating = data.get('rating')
    if not (1 <= rating <= 5):
        return jsonify({'error': 'Invalid rating value'}), 400
    try:
        conn = pyodbc.connect(SQL_CONNECTION_STRING)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO Ratings (video_id, user_id, rating) VALUES (?, ?, ?)", (video_id, current_user['id'], rating))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Rating added successfully!'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/videos/<int:video_id>', methods=['DELETE'])
@token_required
def delete_video(current_user, video_id):
    if current_user['role'] != 'creator':
        return jsonify({'message': 'Unauthorized access!'}), 403
    try:
        conn = pyodbc.connect(SQL_CONNECTION_STRING)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM Videos WHERE id = ? AND uploaded_by = ?", (video_id, current_user['id']))
        conn.commit()
        conn.close()

        # Delete video from Blob Storage
        container_client = blob_service_client.get_container_client("videos")
        container_client.delete_blob(blob_name=str(video_id))

        return jsonify({'message': 'Video deleted successfully!'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)