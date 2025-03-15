#ifndef UTILS_H
#define UTILS_H

#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>

#include <openssl/err.h>

using namespace std;

void write_aes128_key(const string& filename, const vector<unsigned char>& key);
vector<unsigned char> read_aes128_key(const string& filename);
string read_rsa_key(const string& filename);

void handle_openssl_error(const std::string& msg);
#endif