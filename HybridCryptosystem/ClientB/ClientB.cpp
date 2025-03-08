#include <iostream>
#include <boost/asio.hpp>
#include <thread>
#include "crypto.h"
#include "utils.h"  
using namespace std;
using boost::asio::ip::tcp;

boost::asio::io_context io_context;
tcp::socket client_socket(io_context);

vector<unsigned char> aes_key;

vector<unsigned char> iv = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
};

void receive_messages() {
    try {
        while (true) {
            char reply[1024] = { 0 };
            boost::system::error_code error;
            size_t length = client_socket.read_some(boost::asio::buffer(reply), error);
            if (error) break;
			vector<unsigned char> ecrypted_message(reply, reply + length);
			string decrypted_message = aes128_decrypt(ecrypted_message, aes_key, iv);
            cout << "Message from another client: " << decrypted_message << endl;
        }
    }
    catch (exception& e) {
        cerr << "Error: " << e.what() << endl;
    }
}

int main() {
    try {
        client_socket.connect(tcp::endpoint(boost::asio::ip::address::from_string("127.0.0.1"), 12345));
        cout << "Connected to server!\n";

		// Get encrypted AES key from ClientA
        char encrypted_aes_key[256] = { 0 };
        client_socket.read_some(boost::asio::buffer(encrypted_aes_key));
		// Get RSA private key from file
        string private_key_str = read_rsa_key("private_key.txt");
        EVP_PKEY* private_key = load_private_key_from_string(private_key_str);
		// Decrypt AES key with RSA private key
        aes_key = rsa_decrypt(private_key, vector<unsigned char>(encrypted_aes_key, encrypted_aes_key + 256));

		EVP_PKEY_free(private_key);
        thread receiver(receive_messages);

        while (true) {
            string message;
            getline(cin, message);
            if (message == "exit") break;

            vector<unsigned char> encrypted_message = aes128_encrypt(message, aes_key, iv);
            boost::system::error_code error;
            boost::asio::write(client_socket, boost::asio::buffer(encrypted_message), error);
            if (error) break;
        }

        receiver.join();
		client_socket.close();
    }
    catch (exception& e) {
        cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}