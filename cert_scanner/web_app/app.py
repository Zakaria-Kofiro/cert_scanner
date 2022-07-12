import os
import boto3
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

            # Send PEM cert to AWS S3 for file download
            session = boto3.Session(
                aws_access_key_id=os.getenv('DEMO_ACCESS_KEY_ID'),
                aws_secret_access_key=os.getenv('DEMO_SECRET_ACCESS_KEY')
            )
            s3 = session.resource('s3')
            txt_data = bytes(payload['pem_certificate'], encoding='utf-8')
            file_name = f'{query}.pem'
            object = s3.Object('cert-scanner', file_name)
            result = object.put(Body=txt_data)
            if result['ResponseMetadata']['HTTPStatusCode'] == 200:
                download_link = f"https://cert-scanner.s3.us-west-2.amazonaws.com/{file_name}"
            else:
                download_link = None

            issuer = payload['data']['issuer_name']['common_name']
            return render_template('cert.html', query_type=query_type, headers = [query, issuer, "Certificate Found"], data=data, download_link=download_link)
        else:
            return render_template('error.html', reason=payload['data'])

    
        
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)