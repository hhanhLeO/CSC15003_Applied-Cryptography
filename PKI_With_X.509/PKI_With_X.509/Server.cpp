#include "pki.h"

int main() {
    //CA initialization
    CA_Info ca_info;
    if (!setup_ca(ca_info, "ca_private_key.pem", "ca_certificate.pem")) {
        cerr << "CA setup failed!" << endl;
        return 1;
    }
    cout << "CA setup completed. CA key and certificate generated." << endl;

    //generate Client B Key (Normally, Client B would do this)
    EVP_PKEY_CTX* ctx_b = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx_b) {
        handle_openssl_error("EVP_PKEY_CTX_new_id failed for Client B");
        return 1;
    }

    if (EVP_PKEY_keygen_init(ctx_b) <= 0) {
        handle_openssl_error("EVP_PKEY_keygen_init failed for Client B");
        EVP_PKEY_CTX_free(ctx_b);
        return 1;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx_b, 2048) <= 0) {
        handle_openssl_error("EVP_PKEY_CTX_set_rsa_keygen_bits failed for Client B");
        EVP_PKEY_CTX_free(ctx_b);
        return 1;
    }

    EVP_PKEY* client_b_key = nullptr; //khai báo trước
    if (EVP_PKEY_keygen(ctx_b, &client_b_key) <= 0) {
        handle_openssl_error("EVP_PKEY_keygen failed for Client B");
        EVP_PKEY_CTX_free(ctx_b);
        return 1;
    }
    EVP_PKEY_CTX_free(ctx_b); //giải phóng context

    //save Client B's private key to a file (PEM format)
    BIO* key_bio = BIO_new_file("client_b_private_key.pem", "w");
    if (!key_bio) {
        handle_openssl_error("BIO_new_file failed for client B key");
        EVP_PKEY_free(client_b_key);
        return 1;
    }

    if (!PEM_write_bio_PrivateKey(key_bio, client_b_key, nullptr, nullptr, 0, nullptr, nullptr)) {
        handle_openssl_error("PEM_write_bio_PrivateKey failed for Client B");
        BIO_free(key_bio);
        EVP_PKEY_free(client_b_key);
    }

    BIO_free(key_bio);


    //certificate Generation for Client B
    X509* client_b_cert = generate_client_b_certificate(ca_info, client_b_key, "clientb@example.com");
    if (!client_b_cert) {
        std::cerr << "Client B certificate generation failed!" << std::endl;
        EVP_PKEY_free(client_b_key);
        X509_free(ca_info.ca_cert);
        EVP_PKEY_free(ca_info.ca_key);
        return 1;
    }

    //save Client B Certificate
    if (!save_x509_to_file(client_b_cert, "client_b_certificate.pem")) {
        std::cerr << "Failed to save Client B certificate." << std::endl;
        EVP_PKEY_free(client_b_key);
        X509_free(client_b_cert);
        X509_free(ca_info.ca_cert);
        EVP_PKEY_free(ca_info.ca_key);
        return 1;
    }

    std::cout << "Client B certificate generated and saved." << std::endl;

    //cleanup
    EVP_PKEY_free(client_b_key);
    X509_free(client_b_cert);
    X509_free(ca_info.ca_cert);
    EVP_PKEY_free(ca_info.ca_key);

    return 0;
}