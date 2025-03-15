#include "pki.h"
#include "crypto.h"

#include <vector>

#include <openssl/rand.h>

int main() {
    //load Client B's Certificate and extract public key
    X509* client_b_cert = load_x509_from_file("C:\\Users\\Admin\\OneDrive - VNU-HCMUS\\Applied Cryptography\\PKI_With_X.509\\PKI_With_X.509\\client_b_certificate.pem");
    if (!client_b_cert) {
        cerr << "Failed to load Client B certificate." << endl;
        return 1;
    }

    EVP_PKEY* client_b_pubkey = X509_get_pubkey(client_b_cert);
    X509_free(client_b_cert);  //free the certificate after extracting the key

    if (!client_b_pubkey) {
        cerr << "Failed to extract Client B public key." << endl;
        return 1;
    }

    //message to encrypt
    string message = "This is a secret message for Client B.";
    cout << "Original Message: " << message << endl;

    //AES key and IV generation
    vector<unsigned char> aes_key(16); // 128-bit AES key
    vector<unsigned char> iv(16);      // initialization vector
    if (RAND_bytes(aes_key.data(), aes_key.size()) != 1) {
        handle_openssl_error("RAND_bytes failed for AES key");
        EVP_PKEY_free(client_b_pubkey);
        return 1;

    }
    if (RAND_bytes(iv.data(), iv.size()) != 1) {
        handle_openssl_error("RAND_bytes failed for IV");
        EVP_PKEY_free(client_b_pubkey);
        return 1;

    }

    //AES Encryption
    vector<unsigned char> encrypted_message = aes128_encrypt(message, aes_key, iv);
    if (encrypted_message.empty()) {
        cerr << "AES encryption failed." << endl;
        EVP_PKEY_free(client_b_pubkey);
        return 1;
    }

    cout << "AES Encrypted Message (hex): ";
    for (unsigned char c : encrypted_message) {
        printf("%02x", c); //in dưới dạng hex
    }
    cout << endl;

    //RSA Encrypt the AES key with Client B's Public Key
    std::vector<unsigned char> encrypted_aes_key = rsa_encrypt(client_b_pubkey, aes_key);
    if (encrypted_aes_key.empty()) {
        cerr << "RSA encryption of AES key failed." << endl;
        EVP_PKEY_free(client_b_pubkey);
        return 1;
    }

    //send the message and encrypted key (simulate sending)
    cout << "Sending to Client B:" << endl;
    cout << "  Encrypted AES Key (RSA, hex): ";
    for (unsigned char c : encrypted_aes_key) {
        printf("%02x", c); // In dưới dạng hex
    }
    cout << endl;

    cout << "  Encrypted Message (AES, hex): ";
    for (unsigned char c : encrypted_message) {
        printf("%02x", c); //in dưới dạng hex
    }
    cout << endl;

    cout << "  IV (AES, hex): ";
    for (unsigned char c : iv) {
        printf("%02x", c);  //in dưới dạng hex
    }
    cout << endl;

    // Save Encrypted AES Key
    ofstream key_file("encrypted_aes_key.bin", ios::binary);
    if (!key_file.is_open()) {
        cerr << "Could not open encrypted_aes_key.bin for writing." << endl;
        EVP_PKEY_free(client_b_pubkey);
        return 1;
    }
    // Write the *raw bytes* of the encrypted key.
    key_file.write(reinterpret_cast<const char*>(encrypted_aes_key.data()), encrypted_aes_key.size());
    key_file.close();

    // Save Encrypted Message
    ofstream message_file("encrypted_message.bin", ios::binary);
    if (!message_file.is_open()) {
        cerr << "Could not open encrypted_message.bin for writing." << endl;
        EVP_PKEY_free(client_b_pubkey);
        return 1;
    }
    // Write the *raw bytes* of the encrypted message.
    message_file.write(reinterpret_cast<const char*>(encrypted_message.data()), encrypted_message.size());
    message_file.close();

    // Save IV
    ofstream iv_file("iv.bin", ios::binary);
    if (!iv_file.is_open()) {
        cerr << "Could not open iv.bin for writing." << endl;
        EVP_PKEY_free(client_b_pubkey);
        return 1;
    }
    iv_file.write(reinterpret_cast<const char*>(iv.data()), iv.size());
    iv_file.close();

    cout << "Encrypted AES key, message, and IV saved to files." << endl;

    //cleanup
    EVP_PKEY_free(client_b_pubkey);

    return 0;
}