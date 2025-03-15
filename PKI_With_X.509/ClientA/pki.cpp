#include "pki.h"

#include <openssl/rsa.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>

//CA setup
bool setup_ca(CA_Info& ca_info, const string& ca_key_file, const string& ca_cert_file) {
	try {
		//1. generate CA key pair (RSA)
		EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
		if (!ctx) {
			handle_openssl_error("EVP_PKEY_CTX_new_id failed");
			return false;
		}

		if (EVP_PKEY_keygen_init(ctx) <= 0) {
			handle_openssl_error("EVP_PKEY_keygen_init failed");
			EVP_PKEY_CTX_free(ctx);
			return false;
		}

		if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
			handle_openssl_error("EVP_PKEY_CTX_set_rsa_keygen_bits failed");
			EVP_PKEY_CTX_free(ctx);
			return false;
		}

		if (EVP_PKEY_keygen(ctx, &ca_info.ca_key) <= 0) {
			handle_openssl_error("EVP_PKEY_keygen failed");
			EVP_PKEY_CTX_free(ctx);
			return false;
		}

		EVP_PKEY_CTX_free(ctx); // Clean up the context

		//2. create a self-signed X.509 certificate for the CA
		ca_info.ca_cert = X509_new();
		if (!ca_info.ca_cert) {
			handle_openssl_error("X509_new failed");
			EVP_PKEY_free(ca_info.ca_key);
			return false;
		}

		//set certificate version (X.509v3)
		X509_set_version(ca_info.ca_cert, 2);//0-1-2

		//set serial number (unique, use a random number)
		ASN1_INTEGER_set(X509_get_serialNumber(ca_info.ca_cert), 1);

		//set issuer and subject name 
		X509_NAME* ca_name = X509_get_subject_name(ca_info.ca_cert);
		X509_NAME_add_entry_by_txt(ca_name, "C", MBSTRING_ASC, (unsigned char*)"VN", -1, -1, 0);//country
		X509_NAME_add_entry_by_txt(ca_name, "O", MBSTRING_ASC, (unsigned char*)"My CA", -1, -1, 0);//organization
		X509_NAME_add_entry_by_txt(ca_name, "CN", MBSTRING_ASC, (unsigned char*)"My CA Root", -1, -1, 0);//common name
		X509_set_issuer_name(ca_info.ca_cert, ca_name);

		//set validity period (notBefore, notAfter)
		X509_gmtime_adj(X509_get_notBefore(ca_info.ca_cert), 0);
		X509_gmtime_adj(X509_get_notAfter(ca_info.ca_cert), 31536000L);

		//set public key
		X509_set_pubkey(ca_info.ca_cert, ca_info.ca_key);

		//self-sign the certificate
		X509_sign(ca_info.ca_cert, ca_info.ca_key, EVP_sha256());

		//3. save CA key and certificate to files (PEM format)
		if (!save_x509_to_file(ca_info.ca_cert, ca_cert_file)) {
			EVP_PKEY_free(ca_info.ca_key);
			X509_free(ca_info.ca_cert);
			return false;
		}

		BIO* key_bio = BIO_new_file(ca_key_file.c_str(), "w");
		if (!key_bio) {
			handle_openssl_error("BIO_new_file failed");
			EVP_PKEY_free(ca_info.ca_key);
			X509_free(ca_info.ca_cert);
			return false;
		}

		//store CA private key without encrypt
		if (!PEM_write_bio_PrivateKey(key_bio, ca_info.ca_key, nullptr, nullptr, 0, nullptr, nullptr)) {
			handle_openssl_error("PEM_write_bio_PrivateKey");
			BIO_free(key_bio);
			return false;
		}

		BIO_free(key_bio);
		return true;
	}
	catch (const runtime_error& error) {
		cerr << "CA setup failed: " << error.what() << endl;
		return false;
	}
}

//client B certificate generation
X509* generate_client_b_certificate(const CA_Info& ca_info, EVP_PKEY* client_b_key, const string& subject_name) {
	if (!ca_info.ca_cert || !ca_info.ca_key || !client_b_key) {
		cerr << "Invalid CA info or client key" << endl;
		return nullptr;
	}

	X509* client_cert = X509_new();
	if (!client_cert) {
		handle_openssl_error("X509_new failed");
		return nullptr;
	}

	//set certificate version
	X509_set_version(client_cert, 2);

	//set serial number
	ASN1_INTEGER_set(X509_get_serialNumber(client_cert), 2);

	// set issuer name (from CA certificate)
	X509_set_issuer_name(client_cert, X509_get_subject_name(ca_info.ca_cert));

	// set subject name (Client B's information)
	X509_NAME* client_name = X509_get_subject_name(client_cert);
	X509_NAME_add_entry_by_txt(client_name, "C", MBSTRING_ASC, (unsigned char*)"US", -1, -1, 0);
	X509_NAME_add_entry_by_txt(client_name, "O", MBSTRING_ASC, (unsigned char*)"ClientB", -1, -1, 0);
	X509_NAME_add_entry_by_txt(client_name, "CN", MBSTRING_ASC, (unsigned char*)subject_name.c_str(), -1, -1, 0);

	// set validity period
	X509_gmtime_adj(X509_get_notBefore(client_cert), 0);          // Now
	X509_gmtime_adj(X509_get_notAfter(client_cert), 31536000L);  // One year

	// set public key
	X509_set_pubkey(client_cert, client_b_key);

	// sign the certificate with the CA's private key
	if (!X509_sign(client_cert, ca_info.ca_key, EVP_sha256())) {
		handle_openssl_error("X509_sign failed");
		X509_free(client_cert);
		return nullptr;
	}
	return client_cert;
}

//file I/O for certificates and keys (PEM format)
bool save_x509_to_file(X509* cert, const string& filename) {
	BIO* bio = BIO_new_file(filename.c_str(), "w");
	if (!bio) {
		handle_openssl_error("BIO_new_file failed");
		return false;
	}

	if (!PEM_write_bio_X509(bio, cert)) {
		handle_openssl_error("PEM_write_bio_X509 failed");
		BIO_free(bio);
		return false;
	}

	BIO_free(bio);
	return true;
}

X509* load_x509_from_file(const std::string& filename) {
	BIO* bio = BIO_new_file(filename.c_str(), "r");
	if (!bio) {
		handle_openssl_error("BIO_new_file failed");
		return nullptr;
	}
	X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
	BIO_free(bio);
	if (!cert) {
		handle_openssl_error("PEM_read_bio_X509 failed");
		return nullptr;

	}
	return cert;
}

EVP_PKEY* load_private_key_from_file(const std::string& filename, const std::string& password) {
	BIO* bio = BIO_new_file(filename.c_str(), "r");
	if (!bio) {
		handle_openssl_error("BIO_new_file failed");
		return nullptr;
	}

	EVP_PKEY* key = nullptr;
	if (password.empty()) {
		key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
	}
	else {
		key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, (void*)password.c_str());
	}

	BIO_free(bio);
	if (!key) {
		handle_openssl_error("PEM_read_bio_PrivateKey");
		return nullptr;
	}
	return key;
}