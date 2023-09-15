import os
import sys
from OpenSSL import crypto

def set_attribute(subj):
    subj.CN = common_name
    subj.C = "SG"
    subj.ST = "example"
    subj.L = "example"
    subj.O = "example ltd"
    subj.OU = "exampleou"
    subj.emailAddress = "cert_admin@example.com"
    return subj

def generate_certificate_request(common_name, path, multi=False):
    
    key_passphrase = input("Enter a passphrase for the private key: ")

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    if not os.path.isdir(path):
        print("{} is not found, using current dir".format(path))
        path= "."

    key_file =  path + "/" +common_name + ".key"
    csr_file = path + "/" +common_name + ".csr"

    req = crypto.X509Req()
    subj = req.get_subject()
    subj = set_attribute(subj)
    

    req.set_pubkey(key)

    if multi:
        san = ",".join(["DNS:" + domain.strip() for domain in input("Enter multiple domains separated by commas (e.g., domain1.com, domain2.com): ").split(",")])
        req.add_extensions([crypto.X509Extension(b"subjectAltName", False, san.encode())])

    req.sign(key, "sha256")



    with open(key_file, "wb") as keyfile:
        keyfile.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key, cipher=b'AES-256-CBC', passphrase=key_passphrase.encode()))

    with open(csr_file, "wb") as csrfile:
        csrfile.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, req))

def generate_self_signed_certificate(common_name, path, multi=False):
    
    key_passphrase = input("Enter a passphrase for the private key: ")

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    if not os.path.isdir(path):
        print("{} is not found, using current dir".format(path))
        path= "."
    
    key_file =  path + "/" +common_name + ".key"
    crt_file = path + "/" +common_name + ".crt"

    cert = crypto.X509()
    subj = cert.get_subject()
    subj = set_attribute(subj)
 
    if multi:
        san = ",".join(["DNS:" + domain.strip() for domain in input("Enter multiple domains separated by commas (e.g., domain1.com, domain2.com): ").split(",")])
        cert.add_extensions([crypto.X509Extension(b"subjectAltName", False, san.encode())])

    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, "sha256")


    with open(key_file, "wb") as keyfile:
        keyfile.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key, cipher=b'AES-256-CBC', passphrase=key_passphrase.encode()))

    with open(crt_file, "wb") as crtfile:
        crtfile.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

def generate_certificate_with_ca(common_name, path , ca_key_file, ca_crt_file, multi=False):
    
    key_passphrase = input("Enter a passphrase for the private key: ")
    
    key_file =  path + "/" +common_name + ".key"
    crt_file = path + "/" +common_name + ".crt"
    
    ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(ca_crt_file, "rb").read())
    ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, open(ca_key_file, "rb").read())

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    cert = crypto.X509()
    subj = cert.get_subject()
    subj = set_attribute(subj)

    if multi:
        san = ",".join(["DNS:" + domain.strip() for domain in input("Enter multiple domains separated by commas (e.g., domain1.com, domain2.com): ").split(",")])
        cert.add_extensions([crypto.X509Extension(b"subjectAltName", False, san.encode())])

    cert.set_serial_number(1001)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365*24*60*60)
    cert.set_issuer(ca_cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(ca_key, "sha256")



    with open(key_file, "wb") as keyfile:
        keyfile.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key, cipher=b'AES-256-CBC', passphrase=key_passphrase.encode()))

    with open(crt_file, "wb") as crtfile:
        crtfile.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

if __name__ == "__main__":
    option = input("Choose an option (1-4): \n1. Generate public web certificate request\n2. Generate public web certificate request for multiple domains\n3. Generate self-signed certificate\n4. Generate certificate with own CA crt and key\n")

    if option == "1":
        common_name = input("Enter the common name for the certificate: ")
        path = input("Enter output path")
        generate_certificate_request(common_name, path)
    elif option == "2":
        common_name = input("Enter the common name for the certificate: ")
        path = input("Enter output path")
        generate_certificate_request(common_name, path, multi=True)
    elif option == "3":
        common_name = input("Enter the common name for the certificate: ")
        path = input("Enter output path")
        generate_self_signed_certificate(common_name, path)
    elif option == "4":
        common_name = input("Enter the common name for the certificate: ")
        path = input("Enter output path")
        ca_key_file = input("Enter the CA key file name (e.g., ca.key): ")
        ca_crt_file = input("Enter the CA certificate file name (e.g., ca.crt): ")
        generate_certificate_with_ca(common_name, path, ca_key_file, ca_crt_file)
    else:
        print("Invalid option. Please choose an option from 1 to 4.")
