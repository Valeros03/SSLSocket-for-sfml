#pragma once
#include "SSLSocket.hpp"

namespace sf {


class SSLListener {

    private:

        SSL_CTX* ctx;
#ifdef _WIN32
        SOCKET sockfd;
#else
        int sockfd;
#endif
        struct sockaddr_in addr;

        //init the listener using cert and key 
        bool Init(const std::string& cert_file, const std::string& key_file);

       ////////////////////////////////////////////////////////////////////////////////////
       //
       //      Bind the listner to the address
       //
       ///////////////////////////////////////////////////////////////////////////////////
        bool bind(unsigned short port, IpAddress address = IpAddress::Any);

       


       ////////////////////////////////////////////////////////////////////////////////////
       //
       //      Cleans the ssl context, is called only on decostructor
       //
       ///////////////////////////////////////////////////////////////////////////////////
        void CleanSSL();

       ////////////////////////////////////////////////////////////////////////////////////
       //
       //      Creates a new socket for the listener
       //
       ///////////////////////////////////////////////////////////////////////////////////
        void create();



    public:

        //construct a listener with cert_file and key_file
        SSLListener(const std::string& cert_file, const std::string& key_file) {
            Init(cert_file, key_file);
        }

        //construct a listener using another listener with initialized context(this is not a copy construct, in fact a new socket is created)
        SSLListener(const SSLListener& listener) {
            create();
            ctx = listener.ctx;
        }

        //construct from a cotext alredy loaded
        SSLListener(SSL_CTX* context) {
            create();
            ctx = context;
        }


        //decostructor of the listner;
        ~SSLListener() {
            close();
            CleanSSL();
        }

       ////////////////////////////////////////////////////////////////////////////////////
       //
       //      close the socket of the listener
       //
       ///////////////////////////////////////////////////////////////////////////////////
        void close();

        ////////////////////////////////////////////////////////////////////////////////////
        //
        //      make the listner listen from a port and a address; addres is Any(0.0.0.0) by default
        //
        ///////////////////////////////////////////////////////////////////////////////////

        bool listen(unsigned short port, IpAddress address = IpAddress::Any);


       ////////////////////////////////////////////////////////////////////////////////////
       //
       //      make the listener accept a connection in within a timeout in seconds
       //      there's also a function without a timeout that's a blocking function
       //
       ///////////////////////////////////////////////////////////////////////////////////
        bool accept(SSLSocket& other, int seconds_of_timeout);


       ////////////////////////////////////////////////////////////////////////////////////
       //
       //      make the listener accept a connection
       //      there's also a function with a timeout that's a non-blocking function
       //
       ///////////////////////////////////////////////////////////////////////////////////
        bool accept(SSLSocket& other);


    };


}