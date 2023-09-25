import base64
import hashlib
import os
import time
from urllib.parse import urlparse
from flask import Flask, make_response, render_template, request, redirect, session, url_for, flash
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
from OpenSSL import crypto
import csr_database



app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a random secret key for session security
auth = HTTPBasicAuth()

def get_pass():
    with open(".\.id", "r") as file:
        lines = file.readlines()
        return base64.b64decode(lines[0]).decode('utf-8')

print(get_pass())
users = {
    "admin": generate_password_hash(get_pass()),
}


@auth.verify_password
def verify_password(username, password):
    if username in users:
        return check_password_hash(users.get(username), password)
    return False

def set_attribute(subj, common_name):
    subj.CN = common_name
    subj.C = "SG"
    subj.ST = "example"
    subj.L = "example"
    subj.O = "example ltd"
    subj.OU = "exampleou"
    subj.emailAddress = "cert_admin@example.com"
    return subj

@app.route('/')
@auth.login_required
def index():
    return render_template('index.html')

@app.route('/generate_csr', methods=['POST'])
@auth.login_required
def generate_certificate():
    # Extract form data and generate the certificate here
    # Update this function with your certificate generation logic
    common_name = request.form.get('common_name')
    env = request.form.get('env')
    key_passphrase = request.form['passphase']
    multi = request.form.get('multi')
    unique = request.form.get('unique')
    # ... (similarly, extract other form data)

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    req = crypto.X509Req()
    subj = req.get_subject()
    subj = set_attribute(subj, common_name)

    req.set_pubkey(key)

    if multi and request.form.get('domains') != "":
        domains = request.form.get('domains').split(",")
        san = ",".join(["DNS:" + domain.strip() for domain in domains ])
        san_cnf = ""
        for idx in range(len(domains)):
            num = str(idx + 1)
            san_cnf += "DNS."+ num + " = " + domains[idx].strip() + "\n"
            print(san_cnf)

        req.add_extensions([crypto.X509Extension(b"subjectAltName", False, san.encode()),
                            crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
                            crypto.X509Extension(b"keyUsage", False, b"nonRepudiation, digitalSignature, keyEncipherment, dataEncipherment"),
                            crypto.X509Extension(b"extendedKeyUsage", False, b"serverAuth, clientAuth")])
        # req.add_extensions([crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE")])
        # req.add_extensions([crypto.X509Extension(b"keyUsage", False, b"nonRepudiation, digitalSignature, keyEncipherment, dataEncipherment")])
        # req.add_extensions([crypto.X509Extension(b"extendedKeyUsage", False, b"serverAuth, clientAuth")])
    else:
        req.add_extensions([crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
                            crypto.X509Extension(b"keyUsage", False, b"nonRepudiation, digitalSignature, keyEncipherment, dataEncipherment"),
                            crypto.X509Extension(b"extendedKeyUsage", False, b"serverAuth, clientAuth")])

    req.sign(key, "sha256")

    cert = crypto.X509()
    cert.set_serial_number(1000)
    cert.set_issuer(req.get_subject())
    cert.set_subject(req.get_subject())
    cert.set_pubkey(req.get_pubkey())
    cert.sign(key, "sha256")
    key_data = crypto.dump_privatekey(crypto.FILETYPE_PEM, key, cipher='AES-256-CBC', passphrase=key_passphrase.encode())
    csr_data = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)
    cnf_data = f"""[req]
default_bits = 2048
prompt = no
default_md = sha256

distinguished_name = dn
req_extensions = req_ext

[ req_ext ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names		#uncomment if need SAN

[ dn ]
C={subj.C}
ST={subj.ST}
L={subj.L}
O={subj.O}
OU={subj.OU}
emailAddress={subj.emailAddress}
CN={subj.CN}

[ alt_names ]						#uncomment these if need SAN
{san_cnf}
"""
    csr_database.insert_certificate(unique, common_name, env, csr_data.decode("utf-8") , key_data.decode("utf-8"), cnf_data )

    flash(f'Certificate request for "{common_name}" generated successfully', 'success')
    return redirect(url_for('index'))

@app.route('/csr_list', methods=['GET'])
@auth.login_required
def csr_list():
    page = request.args.get('page', 1, type=int)
    total_pages, csr_data = load_certificates(page)
    page_label = f"Page {page} of {total_pages}"

    return render_template('csr_list.html', csr_data=csr_data, page=page, total_pages=total_pages, page_label=page_label)

def load_certificates(page_number):
    page_size = 20  # Number of certificates to display per page
    total_csr = csr_database.get_total_certificate_count()
    total_pages = (total_csr + page_size - 1) // page_size
    csr_data = csr_database.get_certificates(page_number, page_size)
    return total_pages,csr_data

@app.route('/generate_link_csr/<int:csr_id>/<type>', methods=['GET'])
@auth.login_required
def generate_link(csr_id,type):
    record = csr_database.get_certificate_by_id(csr_id)
    
    if record is None:
        flash('data not found', 'error')
        return redirect(url_for('csr_list'))
        
    data = record[3]

    token = hashlib.sha256(os.urandom(32)).hexdigest()

    expiration_time = int(time.time()) + 259200  # 1 hour expiration (adjust as needed)
    # session[token] = {
    #     'token': token,
    #     'data': data,
    #     'expiration_time': expiration_time,
    # }
    csr_database.insert_tokens(record[0],token,data,expiration_time)
    hostname = urlparse(request.base_url).hostname
    url = base64.b64encode(bytes(f'http://{hostname}:5000/download_key/{token}/{record[0]}/{type}', 'utf-8'))

    return redirect(url_for('show_link', url=url))

@app.route('/show_link')
@auth.login_required
def show_link():    
    url = base64.b64decode(request.args.get('url')).decode('utf-8')
    return render_template('show_link.html', url=url)


@app.route('/download_key/<token>/<common_name>/<type>', methods=['GET'])
def download_key(token,common_name,type):
    download_info = csr_database.get_token_data(token)
    if download_info is None:
        flash('Invalid download link', 'error')
        return render_template('404.html')
    else:
        current_time = int(time.time())
        if current_time > download_info[3]:
            flash('Download link has expired', 'error')
            return render_template('404.html')
        else:
            data = download_info[2]

            response = make_response(data)
            response.headers["Content-Disposition"] = f"attachment; filename={common_name}.{type}"
            return response
        
@app.route('/delete_csr/<int:csr_id>')        
def delete_csr(csr_id):
    csr_database.delete_certificate_by_id(csr_id)
    return redirect(request.referrer)

    
@app.route('/download_file/<int:csr_id>/<type>')        
def download_file(csr_id,type):
    record = csr_database.get_certificate_by_id(csr_id)
    if record is None:
        flash('No data', 'error')
        return render_template('404.html')
    else:
        if type == "csr":
            data = record[2]
        if type == "cnf":
            data = record[4]

        response = make_response(data)
        response.headers["Content-Disposition"] = f"attachment; filename={record[0]}.{type}"
        return response
            
if __name__ == '__main__':
    app.run(debug=True)