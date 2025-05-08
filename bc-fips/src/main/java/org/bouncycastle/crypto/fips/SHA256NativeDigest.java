package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.internal.ExtendedDigest;
import org.bouncycastle.crypto.util.dispose.NativeDisposer;
import org.bouncycastle.crypto.util.dispose.NativeReference;
import org.bouncycastle.util.Memoable;

/**
 * SHA256 implementation.
 */
class SHA256NativeDigest
        implements ExtendedDigest, Memoable
{

    protected DigestRefWrapper nativeRef = null;

    SHA256NativeDigest()
    {

        nativeRef = new DigestRefWrapper(makeNative());
        reset();
    }

    SHA256NativeDigest(SHA256NativeDigest src)
    {
        this();
        byte[] state = src.getEncodedState();
        restoreFullState(nativeRef.getReference(), state, 0);
    }

    //
    // From BC-LTS, used for testing in FIPS api only.
    // ----------------------- Start Testing only methods.

    SHA256NativeDigest restoreState(byte[] state, int offset)
    {
        restoreFullState(nativeRef.getReference(), state, offset);
        return this;
    }

    //
    // ----------------------- End Testing only methods.
    //

    @Override
    public String getAlgorithmName()
    {
        return "SHA-256";
    }

    @Override
    public int getDigestSize()
    {
        return getDigestSize(nativeRef.getReference());
    }


    @Override
    public void update(byte in)
    {

        update(nativeRef.getReference(), in);
    }


    @Override
    public void update(byte[] input, int inOff, int len)
    {
        update(nativeRef.getReference(), input, inOff, len);
    }


    @Override
    public int doFinal(byte[] output, int outOff)
    {
        return doFinal(nativeRef.getReference(), output, outOff);
    }


    @Override
    public void reset()
    {
        reset(nativeRef.getReference());
    }


    @Override
    public int getByteLength()
    {
        return getByteLength(nativeRef.getReference());
    }


    @Override
    public Memoable copy()
    {
        return new SHA256NativeDigest(this);
    }

    @Override
    public void reset(Memoable other)
    {
        SHA256NativeDigest dig = (SHA256NativeDigest)other;
        restoreFullState(nativeRef.getReference(), dig.getEncodedState(), 0);
    }


    public byte[] getEncodedState()
    {
        int l = encodeFullState(nativeRef.getReference(), null, 0);
        byte[] state = new byte[l];
        encodeFullState(nativeRef.getReference(), state, 0);
        return state;
    }


    void restoreFullState(byte[] encoded, int offset)
    {
        restoreFullState(nativeRef.getReference(), encoded, offset);
    }

    @Override
    public String toString()
    {
        return "SHA256[Native]()";
    }

    static native long makeNative();

    static native void destroy(long nativeRef);

    static native int getDigestSize(long nativeRef);

    static native void update(long nativeRef, byte in);

    static native void update(long nativeRef, byte[] in, int inOff, int len);

    static native int doFinal(long nativeRef, byte[] out, int outOff);

    static native void reset(long nativeRef);

    static native int getByteLength(long nativeRef);

    static native int encodeFullState(long nativeRef, byte[] buffer, int offset);

    static native void restoreFullState(long reference, byte[] encoded, int offset);


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
            destroy(reference);
        }
    }

    private static class DigestRefWrapper
            extends NativeReference
    {

        public DigestRefWrapper(long reference)
        {
            super(reference);
        }

        @Override
        public Runnable createAction()
        {
            return new Disposer(reference);
        }
    }
}






