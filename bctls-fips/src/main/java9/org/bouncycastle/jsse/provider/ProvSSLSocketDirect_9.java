package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;

class ProvSSLSocketDirect_9
    extends ProvSSLSocketDirect_8
{
    /** This constructor is the one used (only) by ProvSSLServerSocket */
    ProvSSLSocketDirect_9(ContextData contextData, boolean enableSessionCreation,
        boolean useClientMode, ProvSSLParameters sslParameters)
    {
        super(contextData, enableSessionCreation, useClientMode, sslParameters);
    }

    protected ProvSSLSocketDirect_9(ContextData contextData)
    {
        super(contextData);
    }

    protected ProvSSLSocketDirect_9(ContextData contextData, InetAddress address, int port,
        InetAddress clientAddress, int clientPort) throws IOException
    {
        super(contextData, address, port, clientAddress, clientPort);
    }

    protected ProvSSLSocketDirect_9(ContextData contextData, InetAddress address, int port)
        throws IOException
    {
        super(contextData, address, port);
    }

    protected ProvSSLSocketDirect_9(ContextData contextData, String host, int port, InetAddress clientAddress, int clientPort)
        throws IOException, UnknownHostException
    {
        super(contextData, host, port, clientAddress, clientPort);
    }

    protected ProvSSLSocketDirect_9(ContextData contextData, String host, int port)
        throws IOException, UnknownHostException
    {
        super(contextData, host, port);
    }
}
