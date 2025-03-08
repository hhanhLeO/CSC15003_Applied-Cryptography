#pragma once
#include <iostream>
#include <vector>
#include <string>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
using namespace std;

void handleErrors();

vector<unsigned char> aes128_encrypt(const string& plaintext, const vector<unsigned char>& key, const vector<unsigned char>& iv);
string aes128_decrypt(const vector<unsigned char>& ciphertext, const vector<unsigned char>& key, const vector<unsigned char>& iv);

EVP_PKEY* load_public_key_from_string(const string& key_str);
EVP_PKEY* load_private_key_from_string(const string& key_str);

std::vector<unsigned char> rsa_encrypt(EVP_PKEY* public_key, const std::vector<unsigned char>& plaintext);
std::vector<unsigned char> rsa_decrypt(EVP_PKEY* private_key, const std::vector<unsigned char>& ciphertext);