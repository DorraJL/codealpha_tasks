# unsecured.py

import os
from flask import Flask, request, render_template_string, redirect, send_from_directory

app = Flask(__name__)

@app.route('/')
def index():
    return render_template_string('<h1>Welcome to our site!</h1>')

@app.route('/search')
def search():
    query = request.args.get('query')
    result = os.popen('grep {} data.txt'.format(query)).read()  # Code Injection Vulnerability
    return result

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        file = request.files['file']
        file.save(os.path.join('./uploads', file.filename))
        return redirect('/upload-success')
    return render_template_string('<form method="POST" enctype="multipart/form-data">'
                                  '<input type="file" name="file">'
                                  '<input type="submit" value="Upload">'
                                  '</form>')

@app.route('/upload-success')
def upload_success():
    return render_template_string('<h1>File uploaded successfully!</h1>')

@app.route('/hello')
def hello():
    name = request.args.get('name')
    return render_template_string('<h1>Hello, {{ name }}!</h1>', name=name)  # XSS Vulnerability

if __name__ == '__main__':
    app.run(debug=True)

