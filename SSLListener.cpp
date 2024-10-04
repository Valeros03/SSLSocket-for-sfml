#include "SSLListener.hpp"

namespace sf {

    //PRIVATE METHOD:


     ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    bool SSLListener::Init(const std::string& cert_file, const std::string& key_file) {

        // Create SSL context
        ctx = SSL_CTX_new(SSLv23_server_method());
        if (!ctx) {
            std::cerr << "Error creating SSL context: " << std::endl;
            ERR_print_errors_fp(stderr);
            throw(ERR_get_error());
            return false;
        }

        // Load certificate and private key
        if (SSL_CTX_use_certificate_file(ctx, cert_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
            std::cerr << "Error loading certificate file" << std::endl;
            ERR_print_errors_fp(stderr);
            throw(ERR_get_error());
            return false;
        }
        if (SSL_CTX_use_PrivateKey_file(ctx, key_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_fp(stderr);
            throw(ERR_get_error());
            return false;
        }

        // Create socket
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd == -1) {
            std::cerr << "Error creating socket" << std::endl;
            throw(errno);
            return false;
        }

    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    ////////////////////////////////////////////////////////////////////////////////////
    //
    //      Bind the listner to port and address
    //
    ///////////////////////////////////////////////////////////////////////////////////
    bool SSLListener::bind(unsigned short port, IpAddress address)
    {
        // Set up server address structure
        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = htonl(address.toInteger());
        server_addr.sin_port = htons(port);

        // Bind to address
        if (::bind(sockfd, reinterpret_cast<struct sockaddr*>(&server_addr), sizeof(server_addr)) == -1) {
            std::cerr << "Error binding to address" << std::endl;
            return false;
        }
    }

    void SSLListener::close()
    {
        if (sockfd != -1) {
#ifdef _WIN32
            closesocket(sockfd);
#else 
            close(sockfd);
#endif
        }
        sockfd = -1;
        ERR_free_strings();
        EVP_cleanup();

    }

    void SSLListener::CleanSSL()
    {
        if (ctx) {
            SSL_CTX_free(ctx);
            ctx = nullptr;
        }

        // Clean up OpenSSL
        ERR_free_strings();
        EVP_cleanup();
    }

    void SSLListener::create()
    {
        if (sockfd == -1)
            sockfd = socket(AF_INET, SOCK_STREAM, 0);
    }
   


//PUBLIC METHODS:

     ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    bool SSLListener::listen(unsigned short port, IpAddress address)
    {
        close();
        create();

        if (!bind(port, address)) {
            std::cerr << "Error binding the listner to: Port = " << port << ", Address" << address.toString() << "\n";
            return false;
        }

        if (::listen(sockfd, SOMAXCONN) == -1) {
            std::cerr << "Error listening for connections" << std::endl;
            return false;
        }

        return true;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    bool SSLListener::accept(SSLSocket& other, int seconds_of_timeout)
    {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);

        struct timeval timeout;
        timeout.tv_sec = seconds_of_timeout;  // 5 seconds timeout
        timeout.tv_usec = 0;

        int ready = select(sockfd + 1, &readfds, nullptr, nullptr, &timeout);
        if (ready == -1) {
            std::cerr << "Error in select" << std::endl;
            return false;
        }
        else if (ready == 0) {

            return false; // Return false to indicate no connection
        }

        // Accept connection
        socklen_t addr_len = sizeof(other.addr);
        int client_sock = ::accept(sockfd, reinterpret_cast<struct sockaddr*>(&other.addr), &addr_len);
        if (client_sock == -1) {
            std::cerr << "Error accepting connection" << std::endl;
            return false;
        }


        // Create SSL connection
        SSL* ssl_new = SSL_new(ctx);
        SSL_set_fd(ssl_new, client_sock);
        if (SSL_accept(ssl_new) != 1) {
            std::cerr << "Error establishing SSL connection" << std::endl;
            return false;
        }

        other.sockfd = client_sock;
        other.ssl = ssl_new;
        other.ctx = ctx;

        return true;
    }


    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    bool SSLListener::accept(SSLSocket& other)
    {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);

        // Accept connection
        socklen_t addr_len = sizeof(other.addr);
        int client_sock = ::accept(sockfd, reinterpret_cast<struct sockaddr*>(&other.addr), &addr_len);
        if (client_sock == -1) {
            std::cerr << "Error accepting connection" << std::endl;
            return false;
        }


        // Create SSL connection
        SSL* ssl_new = SSL_new(ctx);
        SSL_set_fd(ssl_new, client_sock);
        if (SSL_accept(ssl_new) != 1) {
            std::cerr << "Error establishing SSL connection" << std::endl;
            return false;
        }

        other.sockfd = client_sock;
        other.ssl = ssl_new;
        other.ctx = ctx;

        return true;
    }



    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



}