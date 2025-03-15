#ifndef PKI_H
#define PKI_H

#include "utils.h"

#include <openssl/x509.h>
#include <openssl/pem.h>

using namespace std;

//CA information structure
struct CA_Info {
	EVP_PKEY* ca_key;//CA's private key
	X509* ca_cert;//CA's self-signed certificate
};

//function to set up a basic CA
bool setup_ca(CA_Info&, const string& ca_key_file, const string& ca_cert_file);

//function to generate an X.509 certificate for Client B
X509* generate_client_b_certificate(const CA_Info& ca_info, EVP_PKEY* client_b_key, const string& subject_name);

//function to save an X.509 to file (PEM format)
bool save_x509_to_file(X509* cert, const string& filename);

//function to load an X.509 certificate from a file
X509* load_x509_from_file(const string& filename);

//function to load a private key from a file
EVP_PKEY* load_private_key_from_file(const string& filename, const string& password = "");

#endif // !PKI_H
