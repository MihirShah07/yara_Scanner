from flask import Flask, render_template, request
import os
from yara_script import run_yara
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create upload folder if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/')
def index():
    return render_template('result.html', yara_data=None)

@app.route('/scan', methods=['POST'])
def scan():
    if 'file' not in request.files:
        return render_template('result.html', yara_data=None, error="No file part in the request.")

    uploaded_file = request.files['file']

    if uploaded_file.filename == '':
        return render_template('result.html', yara_data=None, error="No selected file.")

    filename = secure_filename(uploaded_file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    uploaded_file.save(filepath)

    yara_results = run_yara(filepath)

    if "error" in yara_results:
        return render_template('result.html', yara_data=None, error=yara_results["error"])

    return render_template('result.html', yara_data=yara_results)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
