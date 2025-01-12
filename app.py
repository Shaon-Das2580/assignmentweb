from flask import Flask, jsonify, request
import pyodbc
from azure.storage.blob import BlobServiceClient
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Azure SQL Connection String from environment variable
SQL_CONNECTION_STRING = os.environ.get("SQL_CONNECTION_STRING")

# Azure Blob Storage Connection String from environment variable
BLOB_CONNECTION_STRING = os.environ.get("BLOB_CONNECTION_STRING")

# Initialize Blob Service Client
blob_service_client = BlobServiceClient.from_connection_string(BLOB_CONNECTION_STRING)

@app.route('/')
def home():
    return "Backend with SQL and Blob Storage Integration is running!"

# Fetch all users from Azure SQL
@app.route('/users', methods=['GET'])
def get_users():
    try:
        conn = pyodbc.connect(SQL_CONNECTION_STRING)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Users")
        rows = cursor.fetchall()
        users = [{"id": row[0], "username": row[1], "email": row[2]} for row in rows]
        conn.close()
        return jsonify(users)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Upload file to Azure Blob Storage
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['file']
    blob_name = file.filename

    try:
        # Get the container client
        container_client = blob_service_client.get_container_client("videos")

        # Upload the file
        container_client.upload_blob(blob_name, file, overwrite=True)
        return jsonify({"message": f"File '{blob_name}' uploaded successfully!"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# List all blobs in the "videos" container
@app.route('/blobs', methods=['GET'])
def list_blobs():
    try:
        container_client = blob_service_client.get_container_client("videos")
        blobs = container_client.list_blobs()
        blob_list = [{"name": blob.name, "size": blob.size} for blob in blobs]
        return jsonify(blob_list)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
