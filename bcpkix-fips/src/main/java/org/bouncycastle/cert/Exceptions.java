package org.bouncycastle.cert;

import java.io.IOException;

class Exceptions
{
    public static IllegalArgumentException illegalArgumentException(String message, Throwable cause)
    {
        return new IllegalArgumentException(message, cause);
    }

    public static IllegalStateException illegalStateException(String message, Throwable cause)
    {
        return new IllegalStateException(message, cause);
    }

    public static IOException ioException(String message, Throwable cause)
    {
        return new IOException(message, cause);
    }

}
