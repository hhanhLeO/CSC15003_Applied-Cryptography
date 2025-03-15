// ClientB.cpp
#include "pki.h"
#include "crypto.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <sstream> // Thêm thư viện này

int main() {
    // --- Load Client B's Private Key ---
    EVP_PKEY* client_b_privkey = load_private_key_from_file("C:\\Users\\Admin\\OneDrive - VNU-HCMUS\\Applied Cryptography\\PKI_With_X.509\\PKI_With_X.509\\client_b_private_key.pem");

    if (!client_b_privkey) {
        cerr << "Failed to load Client B private key." << endl;
        return 1;
    }

    // Load Encrypted AES Key
    ifstream key_file("C:\\Users\\Admin\\OneDrive - VNU-HCMUS\\Applied Cryptography\\PKI_With_X.509\\ClientA\\encrypted_aes_key.bin", ios::binary);
    if (!key_file.is_open()) {
        cerr << "Could not open encrypted_aes_key.bin for reading." << endl;
        EVP_PKEY_free(client_b_privkey);
        return 1;
    }

    // Read all bytes from the file into a vector
    vector<unsigned char> received_encrypted_aes_key(
        (istreambuf_iterator<char>(key_file)),
        istreambuf_iterator<char>()
    );
    key_file.close();


    // Load Encrypted Message
    ifstream message_file("C:\\Users\\Admin\\OneDrive - VNU-HCMUS\\Applied Cryptography\\PKI_With_X.509\\ClientA\\encrypted_message.bin", ios::binary);
    if (!message_file.is_open()) {
        cerr << "Could not open encrypted_message.bin for reading." << endl;
        EVP_PKEY_free(client_b_privkey);
        return 1;
    }
    vector<unsigned char> received_encrypted_message(
        (istreambuf_iterator<char>(message_file)),
        istreambuf_iterator<char>()
    );
    message_file.close();

    // Load IV
    ifstream iv_file("C:\\Users\\Admin\\OneDrive - VNU-HCMUS\\Applied Cryptography\\PKI_With_X.509\\ClientA\\iv.bin", ios::binary);
    if (!iv_file.is_open()) {
        cerr << "Could not open iv.bin for reading." << endl;
        EVP_PKEY_free(client_b_privkey);
        return 1;
    }
    vector<unsigned char> received_iv(16);
    iv_file.read(reinterpret_cast<char*>(received_iv.data()), received_iv.size());
    iv_file.close();
    if (iv_file.gcount() != 16) { //Check if 16 bytes were read
        cerr << "Error reading IV from file. Incorrect size." << endl;
        EVP_PKEY_free(client_b_privkey);
        return 1;
    }

    // --- Convert hex strings to vectors of bytes ---
    auto hex_to_bytes = [](const string& hex) {
        vector<unsigned char> bytes;
        for (size_t i = 0; i < hex.length(); i += 2) {
            string byte_str = hex.substr(i, 2);
            unsigned char byte = static_cast<unsigned char>(stoul(byte_str, nullptr, 16));
            bytes.push_back(byte);
        }
        return bytes;
    };


    // --- RSA Decrypt the AES Key ---
    vector<unsigned char> decrypted_aes_key = rsa_decrypt(client_b_privkey, received_encrypted_aes_key);
    if (decrypted_aes_key.empty()) {
        cerr << "RSA decryption of AES key failed." << endl;
        EVP_PKEY_free(client_b_privkey);
        return 1;
    }

    // --- AES Decrypt the Message ---
    string decrypted_message = aes128_decrypt(received_encrypted_message, decrypted_aes_key, received_iv);
    if (decrypted_message.empty())
    {
        cerr << "AES decryption failed." << endl;
        EVP_PKEY_free(client_b_privkey);
        return 1;
    }
    cout << "Decrypted Message: " << decrypted_message << endl;


    // --- Cleanup ---
    EVP_PKEY_free(client_b_privkey);
    return 0;
}