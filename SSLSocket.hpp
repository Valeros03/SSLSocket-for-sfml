#pragma once
#include<SFML/Network.hpp>
#include <iostream>
#include <string>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <chrono>
#include <thread>


#include <algorithm>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")


#else
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <fcntl.h> 
#endif

namespace sf {
    class SSLListener;

class SSLSocket{
        friend class SSLListener;
    private:

        SSL_CTX* ctx;
        SSL* ssl;
#ifdef _WIN32
        SOCKET sockfd;
#else
        int sockfd;
#endif
        struct sockaddr_in addr;

        struct PendingPacket
        {
            std::uint32_t          size{};         //!< Data of packet size
            std::size_t            sizeReceived{}; //!< Number of size bytes received so far
            std::vector<std::byte> data;           //!< Data of the packet
        };

        ////////////////////////////////////////////////////////////
        // Member data
        ////////////////////////////////////////////////////////////
        PendingPacket          m_pendingPacket;     //!< Temporary data of the packet currently being received
        std::vector<std::byte> m_blockToSendBuffer;


        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // 
        //        Get the last status socket based on OS Error
        // 
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        Socket::Status SSLSocket::getErrorStatus();

        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // 
        //         Back side of receive function, works like implementation of sf::TcpSocket::receive(...) but uses SSL_Read 
        // 
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        Socket::Status receive(void* data, std::size_t size, std::size_t& received);

        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // 
        //         Back side of Send function, works like implementation of sf::TcpSocket::Send(...) but uses SSL_Write 
        // 
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        Socket::Status send(const void* data, std::size_t size, std::size_t& sent);

        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // 
        //         Back side of Send function, works like implementation of sf::TcpSocket::Send(...) but uses SSL_Write 
        // 
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        bool isBlocking();

        void create();

    public:


        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // 
        //          basic construct for a socket that can be used as a server socket or a client socket
        // 
        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        SSLSocket() : ctx(nullptr), ssl(nullptr), sockfd(-1) {
            m_pendingPacket.size = 0;
            m_pendingPacket.sizeReceived = 0;
            addr = {};
            //if is a server will automaticlly inherits the context from listener socket when accepting connection
            ctx = SSL_CTX_new(SSLv23_client_method());
        }


        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // 
        //          basic deconsturct that kill the socket does not handle the deletation of the SSL context, so use the CleanSSL() function when needed;
        // 
        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        ~SSLSocket() {
            disconnect();
        }

       ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
       // 
       //           connect the function to a specific address to a specific port(there's also a version with a timeout)
       // 
       ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        bool connect(IpAddress address, unsigned short port);

       ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
       // 
       //           connect the function to a specific address to a specific port and a max time to wait the connection(there's also a version without a timeout)
       // 
       ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
       Socket::Status TcpSocket::connect(IpAddress remoteAddress, unsigned short remotePort, Time timeout);


       ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
       // 
       //          retruns the address of the remote connected machine
       // 
       ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        std::string GetClientAddress();


       ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
       // 
       //         Send the contenet of a packet. Returns Status::Partial if the buffer to write is full, Status::Done on succede, Status::Disconnected 
       //         if the other machine has called disconnected
       // 
       ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        Socket::Status send(Packet& packet);


       ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
       // 
       //         Receive the content and put everything in the passed packet. This function is blocking if the socket is the socket is setted as blocking(default)
       //         but can be setted as non blocking using the function SetNonBlocking()
       //         If setted blocking returns: Status::Done on succed, Status::Disconnected if other side has called disconnected, Status::Error on error.
       //         If setted non-blocking returns: same things as blocking, plus Not Ready if not all data has been received from the other side
       // 
       ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        Socket::Status receive(Packet& packet);

        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
       // 
       //        Set the state of the socket as non blocking if true is passed to the function
       //        Set the state of the socket as blocking if false is passed
       // 
       ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        bool SetNonBlocking(bool non_blocking);

       ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
       // 
       //         Close the socket, does not clean SSL_CTX
       // 
       ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        void disconnect();


        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // 
        //        returns the SSL_CTX, can be used if a new listner should be initialized with an alredy loaded context
        // 
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        SSL_CTX* getContext();

    };

}
