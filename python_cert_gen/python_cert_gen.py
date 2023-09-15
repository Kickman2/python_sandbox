import os
import sys
from OpenSSL import crypto

def generate_certificate_request(common_name, key_file, csr_file, multi):
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    req = crypto.X509Req()
    subj = req.get_subject()
    subj.CN = common_name

    req.set_pubkey(key)

    if multi:
        san = ",".join(["DNS:" + domain.strip() for domain in input("Enter multiple domains separated by commas (e.g., domain1.com, domain2.com): ").split(",")])
        req.add_extensions([crypto.X509Extension(b"subjectAltName", False, san.encode())])

    req.sign(key, "sha256")



    with open(key_file, "wb") as keyfile:
        keyfile.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    with open(csr_file, "wb") as csrfile:
        csrfile.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, req))

def generate_self_signed_certificate(common_name, key_file, crt_file):
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    cert = crypto.X509()
    cert.get_subject().CN = common_name
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, "sha256")

    with open(key_file, "wb") as keyfile:
        keyfile.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    with open(crt_file, "wb") as crtfile:
        crtfile.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

def generate_certificate_with_ca(common_name, key_file, crt_file, ca_key_file, ca_crt_file):
    ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(ca_crt_file, "rb").read())
    ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, open(ca_key_file, "rb").read())

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    cert = crypto.X509()
    cert.get_subject().CN = common_name
    cert.set_serial_number(1001)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365*24*60*60)
    cert.set_issuer(ca_cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(ca_key, "sha256")

    with open(key_file, "wb") as keyfile:
        keyfile.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    with open(crt_file, "wb") as crtfile:
        crtfile.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

if __name__ == "__main__":
    option = input("Choose an option (1-4): \n1. Generate public web certificate request\n2. Generate public web certificate request for multiple domains\n3. Generate self-signed certificate\n4. Generate certificate with own CA crt and key\n")

    if option == "1":
        common_name = input("Enter the common name for the certificate: ")
        key_file = input("Enter the key file name (e.g., key.pem): ")
        csr_file = input("Enter the CSR file name (e.g., csr.pem): ")
        generate_certificate_request(common_name, key_file, csr_file)
    elif option == "2":
        common_name = input("Enter the common name for the certificate: ")
        key_file = input("Enter the key file name (e.g., key.pem): ")
        csr_file = input("Enter the CSR file name (e.g., csr.pem): ")
        generate_certificate_request(common_name, key_file, csr_file, multi=True)
    elif option == "3":
        common_name = input("Enter the common name for the certificate: ")
        key_file = input("Enter the key file name (e.g., key.pem): ")
        crt_file = input("Enter the certificate file name (e.g., cert.pem): ")
        generate_self_signed_certificate(common_name, key_file, crt_file)
    elif option == "4":
        common_name = input("Enter the common name for the certificate: ")
        key_file = input("Enter the key file name (e.g., key.pem): ")
        crt_file = input("Enter the certificate file name (e.g., cert.pem): ")
        ca_key_file = input("Enter the CA key file name (e.g., ca.key): ")
        ca_crt_file = input("Enter the CA certificate file name (e.g., ca.crt): ")
        generate_certificate_with_ca(common_name, key_file, crt_file, ca_key_file, ca_crt_file)
    else:
        print("Invalid option. Please choose an option from 1 to 4.")
