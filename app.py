from flask import Flask, render_template, request, jsonify
import os
from yara_script import run_yara

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('result.html', yara_data=None)

@app.route('/scan', methods=['POST'])
def scan():
    file_to_check = request.form['file_name'] + ".txt"

    if not os.path.isfile(file_to_check):
        return render_template('result.html', yara_data=None, error=f"File '{file_to_check}' not found!")

    yara_results = run_yara(file_to_check)

    if "error" in yara_results:
        return render_template('result.html', yara_data=None, error=yara_results["error"])

    return render_template('result.html', yara_data=yara_results)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True) 
