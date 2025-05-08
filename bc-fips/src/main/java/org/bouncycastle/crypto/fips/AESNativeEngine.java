package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.internal.CipherParameters;
import org.bouncycastle.crypto.internal.DataLengthException;
import org.bouncycastle.crypto.internal.MultiBlockCipher;
import org.bouncycastle.crypto.internal.params.KeyParameter;
import org.bouncycastle.crypto.util.dispose.NativeDisposer;
import org.bouncycastle.crypto.util.dispose.NativeReference;

class AESNativeEngine
    implements MultiBlockCipher
{
    protected NativeReference wrapper = null;
    private int keyLen = 0;

    AESNativeEngine()
    {

    }

    @Override
    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException
    {
        if (params instanceof KeyParameter)
        {
            byte[] key = ((KeyParameter)params).getKey();

            switch (key.length)
            {
            case 16:
            case 24:
            case 32:
                wrapper = new ECBNativeRef(makeNative(key.length, forEncryption));
                keyLen = key.length * 8;
                break;

            default:
                throw new IllegalArgumentException("key must be 16, 24 or 32 bytes");
            }

            init(wrapper.getReference(), key);

            return;
        }


        throw new IllegalArgumentException("invalid parameter passed to AES init - " + params.getClass().getName());
    }

    @Override
    public String getAlgorithmName()
    {
        return "AES";
    }

    @Override
    public int getBlockSize()
    {
        return getBlockSize(0);
    }

    @Override
    public int processBlock(byte[] in, int inOff, byte[] out, int outOff)
        throws DataLengthException, IllegalStateException
    {
        if (wrapper == null)
        {
            throw new IllegalStateException("not initialized");
        }

        return process(wrapper.getReference(), in, inOff, 1, out, outOff);
    }

    @Override
    public int getMultiBlockSize()
    {
        return getMultiBlockSize(0);
    }


    @Override
    public int processBlocks(byte[] in, int inOff, int blockCount, byte[] out, int outOff)
        throws DataLengthException, IllegalStateException
    {
        if (wrapper == null)
        {
            throw new IllegalStateException("not initialized");
        }

        return process(wrapper.getReference(), in, inOff, blockCount, out, outOff);
    }

    @Override
    public void reset()
    {
        // skip over spurious resets that may occur before init is called.
        if (wrapper == null)
        {
            return;
        }
        reset(wrapper.getReference());
    }


    private static native void reset(long ref);

    private static native int process(long ref, byte[] in, int inOff, int blocks, byte[] out, int outOff);

    private static native int getMultiBlockSize(long nativeRef);

    private static native int getBlockSize(long ref);

    static native long makeNative(int length, boolean forEncryption);

    static native void dispose(long ref);

    static native void init(long nativeRef, byte[] key);


    private static class Disposer
        extends NativeDisposer
    {
        Disposer(long ref)
        {
            super(ref);
        }

        @Override
        protected void dispose(long reference)
        {
            AESNativeEngine.dispose(reference);
        }
    }

    private static class ECBNativeRef
        extends NativeReference
    {

        public ECBNativeRef(long reference)
        {
            super(reference);
        }

        @Override
        protected Runnable createAction()
        {
            return new Disposer(reference);
        }
    }


    public String toString()
    {
        return "AES[Native](" + keyLen + ")";
    }

}
