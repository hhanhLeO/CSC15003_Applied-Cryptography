#include <iostream>
#include <boost/asio.hpp>
#include <thread>
using namespace std;
using boost::asio::ip::tcp;
boost::asio::io_context io_context;

void handle_client(tcp::socket& socket1, tcp::socket& socket2) {
    try {
        while (true) {
            char data[1024] = { 0 };
            boost::system::error_code error;

			// Get message from client 1
            size_t length = socket1.read_some(boost::asio::buffer(data), error);
            if (error) break;

			// Send message to client 2
            boost::asio::write(socket2, boost::asio::buffer(data, length), error);
            if (error) break;
        }
    }
    catch (exception& e) {
        cerr << "Error: " << e.what() << endl;
    }
}

int main() {
    try {
        tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), 12345));

        cout << "Server is waiting clients...\n";

		// Wait for client 1 to connect
        tcp::socket socket1(io_context);
        acceptor.accept(socket1);
        cout << "ClientA connected!\n";

		// Wait for client 2 to connect
        tcp::socket socket2(io_context);
        acceptor.accept(socket2);
        cout << "ClientB connected!\n";

		// Create 2 threads to handle 2 clients
        thread thread1(handle_client, ref(socket1), ref(socket2));
        thread thread2(handle_client, ref(socket2), ref(socket1));

        thread1.join();
        thread2.join();
    }
    catch (exception& e) {
        cerr << "Error: " << e.what() << endl;
    }

    return 0;
}
