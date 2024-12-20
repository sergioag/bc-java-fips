package org.bouncycastle.crypto;

/**
 * A runtime exception that may be thrown by a finished operation on an
 * UpdateOutputStream if the underlying stream throws an IOException.
 */
public class FinishedException
    extends RuntimeStreamException
{
    /**
     * Base constructor.
     *
     * @param msg a message concerning the exception.
     */
    public FinishedException(String msg)
    {
        super(msg);
    }

    /**
     * Constructor when this exception is due to another one.
     *
     * @param msg a message concerning the exception.
     * @param cause the exception that caused this exception to be thrown.
     */
    public FinishedException(String msg, Throwable cause)
    {
        super(msg, cause);
    }
}
