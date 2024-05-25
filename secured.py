import os
from flask import Flask, request, render_template, redirect, send_from_directory

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/search')
def search():
    query = request.args.get('query')
    if query:
        # Vulnerability Fix: Avoid code injection by using safe file operations
        # Recommendation: Always sanitize user input before using it in commands
        with open('data.txt', 'r') as data_file:
            results = [line.strip() for line in data_file if query in line]
        return render_template('search_results.html', query=query, results=results)
    return render_template('search_results.html', query=query, results=[])

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            # Vulnerability Fix: Ensure secure file upload
            # Recommendation: Validate file type and limit file size
            if allowed_file(file.filename):
                file.save(os.path.join('./uploads', secure_filename(file.filename)))
                return redirect('/upload-success')
            else:
                return "Invalid file type", 400
    return render_template('upload.html')

@app.route('/upload-success')
def upload_success():
    return render_template('upload_success.html')

@app.route('/hello')
def hello():
    name = request.args.get('name')
    return render_template('hello.html', name=name)

if __name__ == '__main__':
    # Vulnerability Fix: Disable Flask debug mode in production
    # Recommendation: Always set debug mode to False in production environments
    app.run(debug=False)
