from flask import Flask, request, jsonify
import os
from yara_script import run_yara
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/scan', methods=['POST'])
def scan():
    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request."}), 400

    uploaded_file = request.files['file']

    if uploaded_file.filename == '':
        return jsonify({"error": "No selected file."}), 400

    filename = secure_filename(uploaded_file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    uploaded_file.save(filepath)

    yara_results = run_yara(filepath)

    if "error" in yara_results:
        return jsonify(yara_results), 400

    return jsonify(yara_results)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
