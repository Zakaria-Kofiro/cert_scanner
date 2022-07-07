from flask import Flask,render_template,request,redirect, url_for
from cert_scanner import scanner
 
app = Flask(__name__)
 
@app.route('/', methods =['POST', 'GET'])
def search():
    if request.method == "POST":
        query = request.form.get("search")
        query_type = request.form.get("choices-single-defaul")

        try:
            if int(query_type) == 0:
                payload = scanner.scan(query) # hostname
            else:
                payload = scanner.scan(None, query) # cert
        except:
            return render_template('error.html', reason='error: hostname not provided or not known')

        if payload['valid']:
            data = scanner.print_payload(payload['data'])
            issuer = payload['data']['issuer_name']['common_name']
            return render_template('cert.html', headers = [query, issuer, "Certificate Found"], data=data)
        else:
            return render_template('error.html', reason=payload['data'])

    
        
    return render_template('index.html')
 
app.run(host='localhost', port=5000)