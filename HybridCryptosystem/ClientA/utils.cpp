#include "utils.h"

void write_aes128_key(const string& filename, const vector<unsigned char>& key) {
	ofstream f(filename, ios::binary);
	if (!f.is_open()) {
		cerr << "Error: could not open file " << filename << " for writing." << endl;
		return;
	}
	for (auto byte : key) {
		f << hex << setw(2) << setfill('0') << (int)byte << " ";
	}
	f.close();
}

vector<unsigned char> read_aes128_key(const string& filename) {
	ifstream f(filename);
	if (!f.is_open()) {
		cerr << "Error: could not open file " << filename << " for reading." << endl;
		return {};
	}
	vector<unsigned char> key;
	unsigned int byte;
	while (f >> hex >> byte) {
		key.push_back(static_cast<unsigned char>(byte));
	}
	return key;
}

string read_rsa_key(const string& filename) {
	ifstream f(filename);
	if (!f.is_open()) {
		cerr << "Error: could not open file " << filename << " for reading." << endl;
		return "";
	}
	stringstream buffer;
	buffer << f.rdbuf();
	return buffer.str();
}