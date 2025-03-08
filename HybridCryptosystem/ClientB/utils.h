#pragma once
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
using namespace std;

void write_aes128_key(const string& filename, const vector<unsigned char>& key);
vector<unsigned char> read_aes128_key(const string& filename);
string read_rsa_key(const string& filename);