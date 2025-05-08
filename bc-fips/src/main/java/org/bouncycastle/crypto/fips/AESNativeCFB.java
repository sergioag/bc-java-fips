package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.internal.CipherParameters;
import org.bouncycastle.crypto.internal.DataLengthException;
import org.bouncycastle.crypto.internal.MultiBlockCipher;
import org.bouncycastle.crypto.internal.StreamCipher;
import org.bouncycastle.crypto.internal.params.KeyParameter;
import org.bouncycastle.crypto.internal.params.KeyParameterImpl;
import org.bouncycastle.crypto.internal.params.ParametersWithIV;
import org.bouncycastle.crypto.internal.test.BasicKatTest;
import org.bouncycastle.crypto.util.dispose.NativeDisposer;
import org.bouncycastle.crypto.util.dispose.NativeReference;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

class AESNativeCFB
        implements StreamCipher, MultiBlockCipher
{
    // self test data
    private static byte[] key = Hex.decode("000102030405060708090a0b0c0d0e0f");
    private static byte[] enc = Hex.decode("c6a13b37878f5b826f4f8162a1c8d879af9d9926f7dac87192b1c4143ad98958");
    private static TestTrigger trigger = new TestTrigger();

    private final int bitSize;
    private CFBRefWrapper referenceWrapper;

    private byte[] oldKey;
    private byte[] oldIv;
    private boolean encrypting;

    private AESNativeCFB()
    {
        this(128);
    }

    private AESNativeCFB(int bitSize)
    {
        this.bitSize = bitSize;
        switch (bitSize)
        {
            case 128:
                break;
            default:
                throw new IllegalArgumentException("native feedback bit size can only be 128");
        }
    }

    @Override
    public void init(boolean forEncryption, CipherParameters params)
            throws IllegalArgumentException
    {

        boolean oldEncrypting = this.encrypting;

        this.encrypting = forEncryption;

        byte[] key = null;
        byte[] iv = null;

        if (params instanceof ParametersWithIV)
        {
            ParametersWithIV ivParam = (ParametersWithIV) params;
            iv = ivParam.getIV();

            if (iv.length > getBlockSize() || iv.length < 1)
            {
                throw new IllegalArgumentException("initialisation vector must be between one and block size length");
            }

            if (iv.length < getBlockSize())
            {
                byte[] newIv = new byte[getBlockSize()];
                System.arraycopy(iv, 0, newIv, newIv.length - iv.length, iv.length);
                iv = newIv;
            }

            oldIv = Arrays.clone(iv);

            if (ivParam.getParameters() != null)
            {
                key = ((KeyParameter) ivParam.getParameters()).getKey();
            }

            if (key != null)
            {
                oldEncrypting = encrypting; // Can change because key is supplied.
                oldKey = Arrays.clone(key);
            }
            else
            {
                // Use old key, it may be null but that is tested later.
                key = oldKey;
            }
        }
        else
        {
            //
            // Change of key.
            //

            if (params instanceof KeyParameter)
            {
                key = ((KeyParameter) params).getKey();
                oldKey = Arrays.clone(key);
                iv = oldIv;
            }

        }

        if (key == null && oldEncrypting != encrypting)
        {
            throw new IllegalArgumentException("cannot change encrypting state without providing key.");
        }

        if (iv == null)
        {
            throw new IllegalArgumentException("iv is null");
        }


        switch (key.length)
        {
            case 16:
            case 24:
            case 32:
                break;
            default:
                throw new IllegalStateException("key must be only 16,24,or 32 bytes long.");
        }


        referenceWrapper = new CFBRefWrapper(makeNative(encrypting, key.length));
        init(referenceWrapper.getReference(), key, iv);

    }


    @Override
    public String getAlgorithmName()
    {
        return "AES/CFB";
    }

    @Override
    public byte returnByte(byte in)
    {
        if (referenceWrapper == null)
        {
            throw new IllegalStateException("not initialized");
        }
        return processByte(referenceWrapper.getReference(), in);
    }

    @Override
    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff)
            throws DataLengthException
    {
//        if (inOff < 0)
//        {
//            throw new DataLengthException("inOff is negative");
//        }
//
//        if (len < 0)
//        {
//            throw new DataLengthException("len is negative");
//        }
//
//        if (outOff < 0)
//        {
//            throw new DataLengthException("outOff is negative");
//        }
//
//        if (inOff + len > in.length)
//        {
//            throw new DataLengthException("input buffer too small");
//        }
//        if (outOff + len > out.length)
//        {
//            throw new OutputLengthException("output buffer too small");
//        }

        if (referenceWrapper == null)
        {
            throw new IllegalStateException("not initialized");
        }


        return processBytes(referenceWrapper.getReference(), in, inOff, len, out, outOff);
    }

    @Override
    public int getBlockSize()
    {
        return bitSize / 8;
    }


    @Override
    public int processBlock(byte[] in, int inOff, byte[] out, int outOff)
            throws DataLengthException, IllegalStateException
    {
        if (referenceWrapper == null)
        {
            throw new IllegalStateException("not initialized");
        }

        return processBytes(referenceWrapper.getReference(), in, inOff, getBlockSize(), out, outOff);
    }

    @Override
    public void reset()
    {
        // skip over spurious resets that may occur before init is called.
        if (referenceWrapper == null)
        {
            return;
        }

        reset(referenceWrapper.getReference());

    }


    @Override
    public int getMultiBlockSize()
    {
        return getNativeMultiBlockSize();
    }

    @Override
    public int processBlocks(byte[] in, int inOff, int blockCount, byte[] out, int outOff)
            throws DataLengthException, IllegalStateException
    {
        if (referenceWrapper == null)
        {
            throw new IllegalStateException("CFB engine not initialized");
        }

        return processBytes(in, inOff, blockCount * getBlockSize(), out, outOff);
    }


    private static native byte processByte(long ref, byte in);

    private static native int processBytes(long ref, byte[] in, int inOff, int len, byte[] out, int outOff)
            throws DataLengthException;

    static native long makeNative(boolean encrypting, int keyLen);

    static native void init(long nativeRef, byte[] key, byte[] iv);

    static native void dispose(long ref);

    static native int getNativeMultiBlockSize();

    private static native void reset(long nativeRef);


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
            AESNativeCFB.dispose(reference);
        }
    }

    private static class CFBRefWrapper
            extends NativeReference
    {

        public CFBRefWrapper(long reference)
        {
            super(reference);
        }

        @Override
        public Runnable createAction()
        {
            return new Disposer(reference);
        }
    }

    public String toString()
    {
        if (oldKey != null)
        {
            return "CFB[Native](AES[Native](" + (oldKey.length * 8) + "))";
        }
        return "CFB[Native](AES[Native](not initialized))";
    }

    static AESNativeCFB newInstance()
    {
        AESNativeCFB engine = new AESNativeCFB();
        if (trigger.triggerTest())
        {
            // FSM_STATE:5.AES.6,"AES ENCRYPT DECRYPT KAT","The module is performing Native AES CFB128 encrypt and decrypt KAT self-test"
            // FSM_TRANS:5.AES.6.0,"CONDITIONAL TEST","NATIVE AES CFB128 ENCRYPT DECRYPT KAT","Invoke Native AES CFB128 Encrypt/Decrypt KAT self-test"
            return SelfTestExecutor.validate(FipsAES.CFB128.getAlgorithm(), engine, new BasicKatTest<AESNativeCFB>()
            {
                @Override
                public boolean hasTestPassed(AESNativeCFB cfbCipher)
                        throws Exception
                {
                    byte[] data = new byte[32];
                    byte[] buf = new byte[32];
                    byte[] iv = new byte[16];

                    cfbCipher.init(true, new ParametersWithIV(new KeyParameterImpl(key), iv));

                    cfbCipher.processBlocks(data, 0, 2, buf, 0);

                    if (!Arrays.areEqual(enc, buf))
                    {
                        return false;
                    }

                    cfbCipher.init(false, new ParametersWithIV(new KeyParameterImpl(key), iv));

                    cfbCipher.processBlocks(enc, 0, 2, buf, 0);

                    return Arrays.areEqual(data, buf);
                }
            });
            // FSM_TRANS:5.AES.6.1,"NATIVE AES CFB128 ENCRYPT DECRYPT KAT","CONDITIONAL TEST","Native AES CFB128 Encrypt / Decrypt KAT self-test successful completion"
            // FSM_TRANS:5.AES.6.2,"NATIVE AES CFB128 ENCRYPT DECRYPT KAT","SOFT ERROR","Native AES CFB128 Encrypt / Decrypt KAT self-test failed"
        }

        return engine;
    }
}
