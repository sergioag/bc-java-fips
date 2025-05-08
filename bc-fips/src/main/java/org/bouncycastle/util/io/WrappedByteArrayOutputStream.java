package org.bouncycastle.util.io;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.util.Arrays;

/**
 * An output stream limited in size to the underlying byte array backing it.
 */
public class WrappedByteArrayOutputStream
    extends OutputStream
{
    private byte[] buf;
    private int start;
    private int offset;

    private boolean copied = false;

    public WrappedByteArrayOutputStream()
    {
    }

    public void setBuffer(byte[] output)
    {
        this.setBuffer(output, 0);
    }

    public void setBuffer(byte[] output, int outputOffset)
    {
        this.buf = output;
        this.start = outputOffset;
        this.offset = outputOffset;
    }

    public void write(byte[] in)
        throws IOException
    {
        System.arraycopy(in, 0, buf, offset, in.length);
        offset += in.length;
    }

    public void write(byte[] in, int inOff, int inLen)
        throws IOException
    {
        System.arraycopy(in, inOff, buf, offset, inLen);
        offset += inLen;
    }

    public void write(int in)
        throws IOException
    {
        buf[offset++] = 0;
    }

    public int size()
    {
        return offset - start;
    }

    /**
     * Return a reference to the internal buffer.'
     *
     * @return a reference to buf.
     */
    public byte[] getBuffer()
    {
        return buf;
    }

    /**
     * Move the offset pointer for the next write.
     *
     * @param delta offset point change
     */
    public void moveOffset(int delta)
    {
         offset += delta;
         if (offset < start || offset > buf.length)
         {
             throw new IllegalStateException("offset outside of buffer range");
         }
    }

    /**
     * Return a trimmed copy of the current buffer, the whole buffer if it's full.
     *
     * @return a copy if full, or a trimmed version.
     */
    public byte[] toTrimmedByteArray()
    {
        if (size() != buf.length)
        {
            byte[] rv = new byte[size()];

            System.arraycopy(buf, start, rv, 0, rv.length);

            copied = true;

            return rv;
        }

        return buf;
    }

    public void erase()
    {
        if (copied)
        {
            Arrays.clear(buf);
            copied = false;
        }
    }

    public int getOffset()
    {
        return offset;
    }
}
