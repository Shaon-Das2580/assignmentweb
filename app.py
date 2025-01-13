from flask import Flask, jsonify, request
from flask_cors import CORS
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
CORS(app, resources={r"/*": {"origins": "https://white-field-071dfd20f.4.azurestaticapps.net"}})

# Secret key for JWT
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_secret_key')

# Azure SQL Connection String from environment variable
SQL_CONNECTION_STRING = os.environ.get("SQL_CONNECTION_STRING")

# Azure Blob Storage Connection String from environment variable
BLOB_CONNECTION_STRING = os.environ.get("BLOB_CONNECTION_STRING")

# Initialize Blob Service Client
blob_service_client = BlobServiceClient.from_connection_string(BLOB_CONNECTION_STRING)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            # Specify algorithms parameter for decoding
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = data['user']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated




@app.route('/')
def home():
    return "Video Sharing Backend API is running!", 200


# User Signup
@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role', 'consumer')

    if not username or not email or not password:
        return jsonify({'error': 'All fields are required!'}), 400

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
    except pyodbc.IntegrityError as e:
        return jsonify({'error': 'Email already exists!'}), 409
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password are required!'}), 400

    try:
        conn = pyodbc.connect(SQL_CONNECTION_STRING)
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password, role FROM Users WHERE email = ?", (email,))
        row = cursor.fetchone()
        conn.close()

        if not row or not bcrypt.checkpw(password.encode('utf-8'), row[2].encode('utf-8')):
            return jsonify({'error': 'Invalid email or password!'}), 401

        # Token generation
        token = jwt.encode(
            {
                'user': {'id': row[0], 'username': row[1], 'role': row[3]},
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            },
            app.config['SECRET_KEY'],
            algorithm="HS256"
        )
        return jsonify({'token': token}), 200
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

        filepath = row[0]  # Example: "4/filename.mov"
        print(f"Generating SAS for filepath: {filepath}")

        sas_token = generate_blob_sas(
            account_name=blob_service_client.account_name,
            container_name="videos",
            blob_name=filepath,  # Ensure no leading slashes
            account_key=blob_service_client.credential.account_key,
            permission=BlobSasPermissions(read=True),
            expiry=datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        )

        url = f"{blob_service_client.primary_endpoint}videos/{filepath}?{sas_token}"
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
@app.route('/videos/<int:video_id>/comments', methods=['GET'])
def get_comments(video_id):
    try:
        conn = pyodbc.connect(SQL_CONNECTION_STRING)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT c.comment, u.username
            FROM Comments c
            JOIN Users u ON c.user_id = u.id
            WHERE c.video_id = ?
        """, (video_id,))
        rows = cursor.fetchall()
        conn.close()
        comments = [{'comment': row[0], 'user': {'username': row[1]}} for row in rows]
        return jsonify(comments), 200
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

@app.route('/videos/<int:video_id>/rate', methods=['POST', 'GET'])
@token_required
def rate_video(current_user, video_id):
    if request.method == 'POST':
        data = request.json
        rating = data.get('rating')
        if not (1 <= rating <= 5):
            return jsonify({'error': 'Invalid rating value'}), 400

        try:
            conn = pyodbc.connect(SQL_CONNECTION_STRING)
            cursor = conn.cursor()

            # Check if the user has already rated this video
            cursor.execute("SELECT id FROM Ratings WHERE video_id = ? AND user_id = ?", (video_id, current_user['id']))
            existing_rating = cursor.fetchone()

            if existing_rating:
                # Update the existing rating
                cursor.execute(
                    "UPDATE Ratings SET rating = ?, rated_at = GETDATE() WHERE id = ?",
                    (rating, existing_rating[0])
                )
            else:
                # Add a new rating
                cursor.execute(
                    "INSERT INTO Ratings (video_id, user_id, rating) VALUES (?, ?, ?)",
                    (video_id, current_user['id'], rating)
                )

            # Calculate the average rating
            cursor.execute("SELECT AVG(rating) FROM Ratings WHERE video_id = ?", (video_id,))
            avg_rating = cursor.fetchone()[0]

            conn.commit()
            conn.close()

            return jsonify({'message': 'Rating submitted successfully!', 'averageRating': avg_rating}), 201
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    elif request.method == 'GET':
        try:
            conn = pyodbc.connect(SQL_CONNECTION_STRING)
            cursor = conn.cursor()

            # Get the average rating
            cursor.execute("SELECT AVG(rating) FROM Ratings WHERE video_id = ?", (video_id,))
            avg_rating = cursor.fetchone()[0] or 0

            # Get the user's specific rating
            cursor.execute("SELECT rating FROM Ratings WHERE video_id = ? AND user_id = ?", (video_id, current_user['id']))
            user_rating = cursor.fetchone()
            user_rating = user_rating[0] if user_rating else 0

            conn.close()
            return jsonify({'averageRating': avg_rating, 'userRating': user_rating}), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500


@app.route('/videos/<int:video_id>', methods=['DELETE'])
@token_required
def delete_video(current_user, video_id):
    if current_user['role'] != 'creator':  # Only creators can delete
        return jsonify({'message': 'Unauthorized access!'}), 403
    try:
        conn = pyodbc.connect(SQL_CONNECTION_STRING)
        cursor = conn.cursor()

        # Ensure the video belongs to the current creator
        cursor.execute("SELECT filepath FROM Videos WHERE id = ? AND uploaded_by = ?", (video_id, current_user['id']))
        row = cursor.fetchone()

        if not row:
            return jsonify({'error': 'Video not found or not authorized to delete!'}), 404

        filepath = row[0]

        # Delete video from the database
        cursor.execute("DELETE FROM Videos WHERE id = ?", (video_id,))
        conn.commit()

        # Delete video from Azure Blob Storage
        container_client = blob_service_client.get_container_client("videos")
        container_client.delete_blob(blob_name=filepath)

        conn.close()
        return jsonify({'message': 'Video deleted successfully!'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/upload', methods=['POST'])
@token_required
def upload_video(current_user):
    if current_user['role'] != 'creator':
        return jsonify({'message': 'Unauthorized access! Only creators can upload videos.'}), 403

    try:
        # Retrieve form data
        title = request.form['title']
        description = request.form.get('description', '')
        file = request.files['file']

        if not file:
            return jsonify({'error': 'No file provided!'}), 400

        # Save the file to Azure Blob Storage
        container_client = blob_service_client.get_container_client("videos")
        blob_name = f"{current_user['id']}/{file.filename}"
        container_client.upload_blob(blob_name, file, overwrite=True)

        # Save video metadata in the database
        conn = pyodbc.connect(SQL_CONNECTION_STRING)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO Videos (title, description, filepath, uploaded_by, metadata) VALUES (?, ?, ?, ?, ?)",
            (title, description, blob_name, current_user['id'], '{"tags": []}')
        )
        conn.commit()
        conn.close()

        return jsonify({'message': 'Video uploaded successfully!'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Error Handling Decorators
@app.errorhandler(404)
def resource_not_found(e):
    return jsonify({'error': 'Resource not found!'}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'An internal server error occurred!'}), 500


@app.route('/videos', methods=['GET'])
def list_videos():
    query = request.args.get('q', '')
    try:
        conn = pyodbc.connect(SQL_CONNECTION_STRING)
        cursor = conn.cursor()
        if query:
            cursor.execute(
                "SELECT id, title, filepath, upload_date FROM Videos WHERE title LIKE ? OR metadata LIKE ?",
                (f"%{query}%", f"%{query}%")
            )
        else:
            cursor.execute(
                "SELECT id, title, filepath, upload_date FROM Videos ORDER BY upload_date DESC"
            )
        rows = cursor.fetchall()
        videos = [{'id': row[0], 'title': row[1], 'filepath': row[2], 'upload_date': row[3]} for row in rows]
        conn.close()
        return jsonify(videos), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
