/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.internal.pqc.lms;

public class LMSException extends Exception
{
    public LMSException()
    {
    }

    public LMSException(String message)
    {
        super(message);
    }

    public LMSException(String message, Throwable cause)
    {
        super(message, cause);
    }

    public LMSException(Throwable cause)
    {
        super(cause);
    }

    public LMSException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace)
    {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
