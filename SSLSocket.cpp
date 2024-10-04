#include "SSLSocket.hpp"

namespace sf {


	//Private Methods:

	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	Socket::Status SSLSocket::receive(void* data, std::size_t size, std::size_t& received) {
        // First clear the variables to fill
        received = 0;

        // Check the destination buffer
        if (!data)
        {

            return Socket::Status::Error;
        }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuseless-cast"
        // Receive a chunk of bytes

        const int sizeReceived = SSL_read(ssl, data, size);
#pragma GCC diagnostic pop
        // Check the number of bytes received
        if (sizeReceived > 0)
        {
            received = static_cast<std::size_t>(sizeReceived);
            return Socket::Status::Done;
        }
        else if (sizeReceived == 0)
        {
            return Socket::Socket::Status::Disconnected;
        }
        else
        {
            // Handle SSL error
            int ssl_error = SSL_get_error(ssl, sizeReceived);
            if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                // No data available at the moment
                return Socket::Status::NotReady;
            }
            else {
                // Other SSL errors
                return getErrorStatus();
            }
        }
	}


    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef _WIN32
    ////////////////////////////////////////////////////////////
    Socket::Status SSLSocket::getErrorStatus()
    {
        // clang-format off
        switch (WSAGetLastError())
        {
            case WSAEWOULDBLOCK:  return Socket::Status::NotReady;
            case WSAEALREADY:     return Socket::Status::NotReady;
            case WSAECONNABORTED: return Socket::Status::Disconnected;
            case WSAECONNRESET:   return Socket::Status::Disconnected;
            case WSAETIMEDOUT:    return Socket::Status::Disconnected;
            case WSAENETRESET:    return Socket::Status::Disconnected;
            case WSAENOTCONN:     return Socket::Status::Disconnected;
            case WSAEISCONN:      return Socket::Status::Done; // when connecting a non-blocking socket
            default:              return Socket::Status::Error;
        }
        // clang-format on
    }
    ////////////////////////////////////////////////////////////
#else
    Socket::Status SSLSocket::getErrorStatus() {
        if ((errno == EAGAIN) || (errno == EINPROGRESS))
            return Socket::Status::NotReady;

        // clang-format off
        switch (errno)
        {
        case EWOULDBLOCK:  return Socket::Status::NotReady;
        case ECONNABORTED: return Socket::Status::Disconnected;
        case ECONNRESET:   return Socket::Status::Disconnected;
        case ETIMEDOUT:    return Socket::Status::Disconnected;
        case ENETRESET:    return Socket::Status::Disconnected;
        case ENOTCONN:     return Socket::Status::Disconnected;
        case EPIPE:        return Socket::Status::Disconnected;
        default:           return Socket::Status::Error;
        }
    }
#endif

    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    Socket::Status SSLSocket::send(const void* data, std::size_t size, std::size_t& sent) {
        // Check the parameters
        if (!data || (size == 0) || ssl == NULL)
        {

            return Socket::Status::Error;
        }

        // Loop until every byte has been sent
        int result = 0;
        for (sent = 0; sent < size; sent += static_cast<std::size_t>(result))
        {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuseless-cast"
            // Send a chunk of data
            result = SSL_write(ssl, data, size - sent);
#pragma GCC diagnostic pop

            // Check for errors
            if (result < 0)
            {
                const Socket::Status status = getErrorStatus();
                int ssl_error = SSL_get_error(ssl, sent);

                if (ssl_error == SSL_ERROR_WANT_WRITE || ssl_error == SSL_ERROR_WANT_READ) {
                    return Socket::Status::NotReady;
                }


                else if ((status == Socket::Status::NotReady) && sent)
                    return Socket::Status::Partial;

                return status;
            }
        }

        return Socket::Status::Done;
    }


    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


    void SSLSocket::create() {
        if (sockfd == -1)
            sockfd = socket(AF_INET, SOCK_STREAM, 0);
    }

    
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


    //Public Method:

    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    bool SSLSocket::connect(IpAddress address, unsigned short port) {
        disconnect();

        create();


#ifdef _WIN32
    addr = sockaddr_in();
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(address.toInteger());
#else
    memset(&addr, 0, sizeof(addr));   // Inizializza la struttura a zero
    addr.sin_family = AF_INET;        // Famiglia di indirizzi IPv4
    addr.sin_port = htons(port);      // Conversione in formato di rete della porta

    // Converte l'indirizzo IP da stringa a binario e lo imposta nella struttura
    if (inet_pton(AF_INET, address.c_str(), &addr.sin_addr) <= 0) {
        // Gestisci l'errore in caso di fallimento della conversione dell'indirizzo
        perror("inet_pton error");
    }
#endif
        if (::connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {

            perror("Connection failed");
            return 0;
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sockfd);

        if (SSL_connect(ssl) != 1) {
            ERR_print_errors_fp(stderr);
            return 0;
        }
        return 1;
    }


    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


Socket::Status TcpSocket::connect(IpAddress remoteAddress, unsigned short remotePort, Time timeout)
{
    // Disconnect the socket if it is already connected
    disconnect();

    // Create the internal socket if it doesn't exist
    create();

    // Create the remote address
#ifdef _WIN32
    addr = sockaddr_in();
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(address.toInteger());
#else
    memset(&addr, 0, sizeof(addr));   // Inizializza la struttura a zero
    addr.sin_family = AF_INET;        // Famiglia di indirizzi IPv4
    addr.sin_port = htons(port);      // Conversione in formato di rete della porta

    // Converte l'indirizzo IP da stringa a binario e lo imposta nella struttura
    if (inet_pton(AF_INET, address.c_str(), &addr.sin_addr) <= 0) {
        // Gestisci l'errore in caso di fallimento della conversione dell'indirizzo
        perror("inet_pton error");
    }
#endif

    if (timeout <= Time::Zero)
    {
        // ----- We're not using a timeout: just try to connect -----

        // Connect the socket
        if (::connect(sockfd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == -1)
            return getErrorStatus();

         // Set socket back to blocking mode
        if (!SetNonBlocking(false)) {
            std::cerr << "Error setting socket to blocking mode" << std::endl;
            return Socket::Status::Error;
        }

        // Create SSL connection
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sockfd);
        if (SSL_connect(ssl) != 1) {
            std::cerr << "Error establishing SSL connection" << std::endl;
            return Socket::Status::Error;
        }

        
        return Socket::Status::Done;
    }

    // ----- We're using a timeout: we'll need a few tricks to make it work -----

    // Save the previous blocking state
    const bool blocking = isBlocking();

    // Switch to non-blocking to enable our connection timeout
    if (blocking)
        setNonBlocking(true);

    // Try to connect to the remote address
    if (::connect(sockfd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) >= 0)
    {
        // We got instantly connected! (it may no happen a lot...)
          // Create SSL connection
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sockfd);
        if (SSL_connect(ssl) != 1) {
            std::cerr << "Error establishing SSL connection" << std::endl;
            return Socket::Status::Error;
        }

        
 
        setNonBlocking(blocking);
        return Socket::Status::Done;
    }

    // Get the error status
    Socket::Status status = getErrorStatus();

    // If we were in non-blocking mode, return immediately
    if (!blocking)
        return status;

    // Otherwise, wait until something happens to our socket (success, timeout or error)
    if (status == Socket::Status::NotReady)
    {
        // Setup the selector
        fd_set selector;
        FD_ZERO(&selector);
        FD_SET(sockfd, &selector);

        // Setup the timeout
        timeval time{};
        time.tv_sec  = static_cast<long>(timeout.asMicroseconds() / 1000000);
        time.tv_usec = static_cast<int>(timeout.asMicroseconds() % 1000000);

        // Wait for something to write on our socket (which means that the connection request has returned)
        if (::select(static_cast<int>(sockfd + 1), nullptr, &selector, nullptr, &time) > 0)
        {
            // At this point the connection may have been either accepted or refused.
            // To know whether it's a success or a failure, we must check the address of the connected peer
            if (getRemoteAddress().has_value())
            {
                // Connection accepted
                   // Create SSL connection
                 ssl = SSL_new(ctx);
                 SSL_set_fd(ssl, sockfd);
                 if (SSL_connect(ssl) != 1) {
                     std::cerr << "Error establishing SSL connection" << std::endl;
                     return Socket::Status::Error;
                 }
                status = Socket::Status::Done;
            }
            else
            {
                // Connection refused
                status = Socket::Status::Error;
            }
        }
        else
        {
            // Failed to connect before timeout is over
            status = Socket::Status::NotReady;
        }
    }

    // Switch back to blocking mode
    setNonBlocking(false);

    return status;
    }

    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    std::string SSLSocket::GetClientAddress() {
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(addr.sin_addr), client_ip, INET_ADDRSTRLEN);
        return std::string(client_ip);
    }


    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


    Socket::Status SSLSocket::send(Packet& packet)
    {
        std::size_t size = packet.getDataSize();
        const void* data = packet.getData();

        // First convert the packet size to network byte order
        std::uint32_t packetSize = htonl(static_cast<std::uint32_t>(size));

        // Allocate memory for the data block to send
        m_blockToSendBuffer.resize(sizeof(packetSize) + size);

        // Copy the packet size and data into the block to send
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wnull-dereference" // False positive.
        std::memcpy(m_blockToSendBuffer.data(), &packetSize, sizeof(packetSize));
#pragma GCC diagnostic pop
        if (size > 0)
            std::memcpy(m_blockToSendBuffer.data() + sizeof(packetSize), data, size);

        // These warnings are ignored here for portability, as even on Windows the
        // signature of `send` might change depending on whether Win32 or MinGW is
        // being used.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuseless-cast"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
    // Send the data block
        std::size_t  sent;
        const Socket::Status status = send(m_blockToSendBuffer.data() + packet.m_sendPos,
            m_blockToSendBuffer.size() - packet.m_sendPos,
            sent);
#pragma GCC diagnostic pop
#pragma GCC diagnostic pop

        // In the case of a partial send, record the location to resume from
        if (status == Socket::Status::Partial)
        {
            packet.m_sendPos += sent;
        }
        else if (status == Socket::Status::Done)
        {
            packet.m_sendPos = 0;
        }

        return status;
    }


    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


    Socket::Status SSLSocket::receive(Packet& packet) {
        packet.clear();

        // We start by getting the size of the incoming packet
        std::uint32_t packetSize = 0;
        std::size_t   received = 0;
        if (m_pendingPacket.sizeReceived < sizeof(m_pendingPacket.size))
        {
            // Loop until we've received the entire size of the packet
            // (even a 4 byte variable may be received in more than one call)
            while (m_pendingPacket.sizeReceived < sizeof(m_pendingPacket.size))
            {
                char* data = reinterpret_cast<char*>(&m_pendingPacket.size) + m_pendingPacket.sizeReceived;
                const Socket::Status status = receive(data, sizeof(m_pendingPacket.size) - m_pendingPacket.sizeReceived, received);
                m_pendingPacket.sizeReceived += received;

                if (status != Socket::Status::Done)
                    return status;
            }

            // The packet size has been fully received
            packetSize = ntohl(m_pendingPacket.size);
        }
        else
        {
            // The packet size has already been received in a previous call
            packetSize = ntohl(m_pendingPacket.size);
        }

        // Loop until we receive all the packet data
        char buffer[1024];
        while (m_pendingPacket.data.size() < packetSize)
        {
            // Receive a chunk of data
            const std::size_t sizeToGet = (packetSize - m_pendingPacket.data.size()) < sizeof(buffer) ? packetSize - m_pendingPacket.data.size() : sizeof(buffer);
            const Socket::Status      status = receive(buffer, sizeToGet, received);
            if (status != Socket::Status::Done)
                return status;

            // Append it into the packet
            if (received > 0)
            {
                m_pendingPacket.data.resize(m_pendingPacket.data.size() + received);
                std::byte* begin = m_pendingPacket.data.data() + m_pendingPacket.data.size() - received;
                std::memcpy(begin, buffer, received);
            }
        }

        // We have received all the packet data: we can copy it to the user packet
        if (!m_pendingPacket.data.empty())
            packet.append(m_pendingPacket.data.data(), m_pendingPacket.data.size());

        // Clear the pending packet data
        m_pendingPacket = PendingPacket();

        return Socket::Status::Done;
    }


    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    
    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    bool SSLSocket::SetNonBlocking(bool non_blocking) {
#ifdef _WIN32
        u_long mode = non_blocking ? 1 : 0;
        if (ioctlsocket(sockfd, FIONBIO, &mode) != NO_ERROR) {
            std::cerr << "Error setting socket to " << (non_blocking ? "non-" : "") << "blocking mode" << std::endl;
            return false;
        }
#else
        int flags = fcntl(sockfd, F_GETFL, 0);
        if (flags == -1) {
            std::cerr << "Error getting socket flags" << std::endl;
            return false;
        }
        if (non_blocking) {
            if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1) {
                std::cerr << "Error setting socket to non-blocking mode" << std::endl;
                return false;
            }
        }
        else {
            if (fcntl(sockfd, F_SETFL, flags & ~O_NONBLOCK) == -1) {
                std::cerr << "Error setting socket to blocking mode" << std::endl;
                return false;
            }
        }
#endif
        return true;
    }


    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


    void SSLSocket::disconnect() {
        if (ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
            ssl = nullptr;
        }
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


     /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



    SSL_CTX* SSLSocket::getContext()
    {
        return ctx;
    }


    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


}