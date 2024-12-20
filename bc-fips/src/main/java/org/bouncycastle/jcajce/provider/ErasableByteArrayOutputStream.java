package org.bouncycastle.jcajce.provider;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.util.Arrays;

class ErasableByteArrayOutputStream
    extends ByteArrayOutputStream
{
    public void erase()
    {
        // this will also erase the checksum from memory.
        Arrays.clear(buf);
        this.reset();
    }

    public int copy(byte[] output, int outputOffset)
    {
        System.arraycopy(buf, 0, output, outputOffset, size());

        return size();
    }
}
