#include "crypto.h"

// Handle errors in OpenSSL
void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

// Encryption
vector<unsigned char> aes128_encrypt(const string& plaintext, const vector<unsigned char>& key, const vector<unsigned char>& iv) {
    // Check the length of key and iv
    if (key.size() != 16) {
        cerr << "The length of key must be 16 bytes" << endl;
        return {};
    }
    if (iv.size() != 16) {
        cerr << "The length of iv must be 16 bytes" << endl;
        return {};
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handleErrors();
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key.data(), iv.data())) {
        EVP_CIPHER_CTX_free(ctx);
        handleErrors();
    }

    // Cấp phát bộ nhớ cho ciphertext (có thể lớn hơn plaintext do padding)
    vector<unsigned char> ciphertext(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_128_cbc()));
    int len = 0;
    int ciphertext_len = 0;

    // Thực hiện mã hóa
    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        handleErrors();
    }
    ciphertext_len = len;

    // Hoàn thành mã hóa
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        handleErrors();
    }
    ciphertext_len += len;

    // Giải phóng context
    EVP_CIPHER_CTX_free(ctx);

    // Cắt bớt vector để có kích thước chính xác
    ciphertext.resize(ciphertext_len);

    return ciphertext;
}

// Decryption
string aes128_decrypt(const vector<unsigned char>& ciphertext, const vector<unsigned char>& key, const vector<unsigned char>& iv) {
    // Check the length of key and iv
    if (key.size() != 16) {
        cerr << "The length of key must be 16 bytes" << endl;
        return "";
    }
    if (iv.size() != 16) {
        cerr << "The length of iv must be 16 bytes" << endl;
        return "";
    }

    // Tạo context cho EVP
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handleErrors();
    }

    // Khởi tạo hoạt động giải mã
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key.data(), iv.data())) {
        EVP_CIPHER_CTX_free(ctx);
        handleErrors();
    }

    // Cấp phát bộ nhớ cho plaintext
    vector<unsigned char> plaintext(ciphertext.size());
    int len = 0;
    int plaintext_len = 0;

    // Thực hiện giải mã
    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        handleErrors();
    }
    plaintext_len = len;

    // Hoàn thành giải mã
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        handleErrors();
    }
    plaintext_len += len;

    // Giải phóng context
    EVP_CIPHER_CTX_free(ctx);

    // Chuyển kết quả thành chuỗi
    string result(reinterpret_cast<char*>(plaintext.data()), plaintext_len);

    return result;
}

EVP_PKEY* load_public_key_from_string(const string& key_str) {
    BIO* bio = BIO_new_mem_buf(key_str.c_str(), -1);
    if (!bio) return nullptr;
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return pkey;
}

EVP_PKEY* load_private_key_from_string(const string& key_str) {
    BIO* bio = BIO_new_mem_buf(key_str.c_str(), -1);
    if (!bio) return nullptr;
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return pkey;
}

std::vector<unsigned char> rsa_encrypt(EVP_PKEY* public_key, const std::vector<unsigned char>& plaintext) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(public_key, nullptr);
    if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0) {
        handleErrors();
    }

    size_t outlen;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, plaintext.data(), plaintext.size()) <= 0) {
        handleErrors();
    }

    std::vector<unsigned char> ciphertext(outlen);
    if (EVP_PKEY_encrypt(ctx, ciphertext.data(), &outlen, plaintext.data(), plaintext.size()) <= 0) {
        handleErrors();
    }

    EVP_PKEY_CTX_free(ctx);
    ciphertext.resize(outlen); // Cắt bỏ phần thừa nếu có
    return ciphertext;
}

// Giải mã vector<unsigned char> bằng khóa riêng
std::vector<unsigned char> rsa_decrypt(EVP_PKEY* private_key, const std::vector<unsigned char>& ciphertext) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(private_key, nullptr);
    if (!ctx || EVP_PKEY_decrypt_init(ctx) <= 0) {
        handleErrors();
    }

    size_t outlen;
    if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, ciphertext.data(), ciphertext.size()) <= 0) {
        handleErrors();
    }

    std::vector<unsigned char> plaintext(outlen);
    if (EVP_PKEY_decrypt(ctx, plaintext.data(), &outlen, ciphertext.data(), ciphertext.size()) <= 0) {
        handleErrors();
    }

    EVP_PKEY_CTX_free(ctx);
    plaintext.resize(outlen); // Cắt bỏ phần thừa nếu có
    return plaintext;
}
