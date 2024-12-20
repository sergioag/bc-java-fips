package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.io.OutputStream;

class WrappedByteArrayOutputStream
    extends OutputStream
{
    private final ErasableByteArrayOutputStream ebOut = new ErasableByteArrayOutputStream();

    private byte[] buf;
    private int start;
    private int offset;

    public WrappedByteArrayOutputStream()
    {
    }

    public void setWrappedMode(byte[] output, int outputOffset)
    {
        this.buf = output;
        this.start = outputOffset;
        this.offset = outputOffset;
    }

    public void clearWrappedMode()
    {
        this.buf = null;
    }

    public void write(byte[] in)
        throws IOException
    {
        if (buf != null)
        {
            System.arraycopy(in, 0, buf, offset, in.length);
            offset += in.length;
        }
        else
        {
            ebOut.write(in);
        }
    }

    public void write(byte[] in, int inOff, int inLen)
        throws IOException
    {
        if (buf != null)
        {
            System.arraycopy(in, inOff, buf, offset, inLen);
            offset += inLen;
        }
        else
        {
            ebOut.write(in, inOff, inLen);
        }
    }

    public void write(int in)
        throws IOException
    {
        if (buf != null)
        {
            buf[offset++] = 0;
        }
        else
        {
            ebOut.write(in);
        }
    }

    public void reset()
    {
        offset = start;
        ebOut.reset();
    }

    public int size()
    {
        if (buf != null)
        {
            return offset - start;
        }
        else
        {
            return ebOut.size();
        }
    }

    public byte[] toByteArray()
    {
        if (buf != null)
        {
            throw new IllegalStateException("attempt to call toByteArray in wrap mode");
        }
        return ebOut.toByteArray();
    }

    public void erase()
    {
        ebOut.erase();
    }
}
