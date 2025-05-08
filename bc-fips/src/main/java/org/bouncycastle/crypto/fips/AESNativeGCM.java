package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.internal.BlockCipher;
import org.bouncycastle.crypto.internal.CipherParameters;
import org.bouncycastle.crypto.internal.DataLengthException;
import org.bouncycastle.crypto.internal.InvalidCipherTextException;
import org.bouncycastle.crypto.internal.modes.AEADBlockCipher;
import org.bouncycastle.crypto.internal.params.AEADParameters;
import org.bouncycastle.crypto.internal.params.KeyParameter;
import org.bouncycastle.crypto.internal.params.KeyParameterImpl;
import org.bouncycastle.crypto.internal.params.ParametersWithIV;
import org.bouncycastle.crypto.internal.test.BasicKatTest;
import org.bouncycastle.crypto.util.dispose.NativeDisposer;
import org.bouncycastle.crypto.util.dispose.NativeReference;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

class AESNativeGCM
        implements AEADBlockCipher
{
    private GCMRefWrapper refWrapper;
    private int macSize = 0;

    private byte[] nonce;

    private byte[] lastKey;

    private byte[] initialAssociatedText;

    private boolean forEncryption = false;

    private boolean initialised = false;

    private byte[] keptMac = null;

    private AESNativeGCM()
    {
        // locked down so that only getInstance can be used.
    }

    @Override
    public BlockCipher getUnderlyingCipher()
    {
        BlockCipher engine = FipsAES.ENGINE_PROVIDER.createEngine();
        if (lastKey != null)
        {
            engine.init(true, new KeyParameterImpl(lastKey));
        }
        return engine;
    }

    public void init(boolean forEncryption, CipherParameters params)
            throws IllegalArgumentException
    {
        this.forEncryption = forEncryption;
        KeyParameter keyParam;
        byte[] newNonce = null;
        keptMac = null;

        if (params instanceof AEADParameters)
        {
            AEADParameters param = (AEADParameters) params;

            newNonce = param.getNonce();
            initialAssociatedText = param.getAssociatedText();

            int macSizeBits = param.getMacSize();
            if (macSizeBits < 32 || macSizeBits > 128 || macSizeBits % 8 != 0)
            {
                throw new IllegalArgumentException("invalid value for MAC size: " + macSizeBits);
            }

            macSize = macSizeBits;
            keyParam = param.getKey();
        }
        else if (params instanceof ParametersWithIV)
        {
            ParametersWithIV param = (ParametersWithIV) params;

            newNonce = param.getIV();
            initialAssociatedText = null;
            macSize = 128;
            keyParam = (KeyParameter) param.getParameters();
        }
        else
        {
            throw new IllegalArgumentException("invalid parameters passed to GCM");
        }


        if (newNonce == null || newNonce.length < 12)
        {
            throw new IllegalArgumentException("IV must be at least 12 bytes");
        }

        if (forEncryption)
        {
            if (nonce != null && Arrays.areEqual(nonce, newNonce))
            {
                if (keyParam == null)
                {
                    throw new IllegalArgumentException("cannot reuse nonce for GCM encryption");
                }
                if (lastKey != null && Arrays.areEqual(lastKey, keyParam.getKey()))
                {
                    throw new IllegalArgumentException("cannot reuse nonce for GCM encryption");
                }
            }
        }

        nonce = newNonce;
        if (keyParam != null)
        {
            lastKey = keyParam.getKey();
        }


        switch (lastKey.length)
        {
            case 16:
            case 24:
            case 32:
                break;
            default:
                throw new IllegalStateException("key must be only 16,24,or 32 bytes long.");
        }

        initRef(lastKey.length);


        initNative(
                refWrapper.getReference(),
                forEncryption, lastKey,
                nonce, initialAssociatedText, macSize);


        initialised = true;
    }


    private void initRef(int keySize)
    {
        refWrapper = new GCMRefWrapper(makeNative(keySize, forEncryption));
    }


    @Override
    public String getAlgorithmName()
    {
        return "AES/GCM";
    }

    @Override
    public void processAADByte(byte in)
    {
        if (refWrapper == null)
        {
            throw new IllegalStateException("GCM is uninitialized");
        }
        processAADByte(refWrapper.getReference(), in);
    }


    @Override
    public void processAADBytes(byte[] in, int inOff, int len)
    {
//        if (inOff < 0)
//        {
//            throw new IllegalArgumentException("inOff is negative");
//        }
//
//        if (len < 0)
//        {
//            throw new IllegalArgumentException("len is negative");
//        }
//
//        if (inOff + len > in.length)
//        {
//            throw new IllegalArgumentException("inOff + len past end of data");
//        }
//
        if (refWrapper == null)
        {
            throw new IllegalStateException("GCM is uninitialized");
        }

        processAADBytes(refWrapper.getReference(), in, inOff, len);
    }


    @Override
    public int processByte(byte in, byte[] out, int outOff)
            throws DataLengthException
    {
//        if (outOff < 0)
//        {
//            throw new IllegalArgumentException("outOff is negative");
//        }
//
//        if (outOff > out.length)
//        {
//            throw new IllegalArgumentException("offset past end of output array");
//        }

        if (refWrapper == null)
        {
            throw new IllegalStateException("GCM is uninitialized");
        }

        return processByte(refWrapper.getReference(), in, out, outOff);
    }


    @Override
    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff)
            throws DataLengthException
    {
//        if (inOff < 0)
//        {
//            throw new IllegalStateException("inOff is negative");
//        }
//
//        if (len < 0)
//        {
//            throw new IllegalStateException("len is negative");
//        }
//
//        if (outOff < 0)
//        {
//            throw new IllegalStateException("outOff is negative");
//        }
//
//
//        if (inOff + len > in.length)
//        {
//            throw new IllegalStateException("inOff + len is past end of input");
//        }
//
//        if (outOff > 0 && (out == null || outOff > out.length))
//        {
//            throw new IllegalArgumentException("offset past end of output array");
//        }

        if (refWrapper == null)
        {
            throw new IllegalStateException("GCM is uninitialized");
        }

        return processBytes(refWrapper.getReference(), in, inOff, len, out, outOff);
    }


    @Override
    public int doFinal(byte[] out, int outOff)
            throws IllegalStateException, InvalidCipherTextException
    {

//        if (outOff < 0)
//        {
//            throw new IllegalArgumentException("outOff is negative");
//        }
//
//
//        if (outOff > out.length)
//        {
//            throw new IllegalArgumentException("offset past end of output array");
//        }

        checkStatus();


        int len = doFinal(refWrapper.getReference(), out, outOff);

        //
        // BlockCipherTest, testing ShortTagException.
        //

        resetKeepMac();
        return len;
    }


    @Override
    public byte[] getMac()
    {
        if (keptMac != null)
        {
            return Arrays.clone(keptMac);
        }
        return getMac(refWrapper.getReference());
    }


    @Override
    public int getUpdateOutputSize(int len)
    {
        return getUpdateOutputSize(refWrapper.getReference(), len);
    }


    @Override
    public int getOutputSize(int len)
    {
        return getOutputSize(refWrapper.getReference(), len);
    }


    @Override
    public void reset()
    {
        if (refWrapper == null)
        {
            // deal with reset being called before init.
            return;
        }

        reset(refWrapper.getReference());
        initialised = false;
    }

    private void resetKeepMac()
    {
        if (refWrapper == null)
        {
            // deal with reset being called before init.
            return;
        }

        keptMac = getMac();
        reset(refWrapper.getReference());
    }


    private void checkStatus()
    {
        if (!initialised)
        {
            if (forEncryption)
            {
                throw new IllegalStateException("GCM cipher cannot be reused for encryption");
            }
            throw new IllegalStateException("GCM cipher needs to be initialised");
        }
    }

    private native void reset(long ref);

    static native void initNative(
            long reference,
            boolean forEncryption,
            byte[] keyParam,
            byte[] nonce,
            byte[] initialAssociatedText,
            int macSizeBits);

    static native long makeNative(int keySize, boolean forEncryption);

    static native void dispose(long nativeRef);

    private static native void processAADByte(long ref, byte in);

    private static native void processAADBytes(long ref, byte[] in, int inOff, int len);

    private static native int processByte(long ref, byte in, byte[] out, int outOff);

    private static native int processBytes(long ref, byte[] in, int inOff, int len, byte[] out, int outOff);

    private static native int doFinal(long ref, byte[] out, int outOff);

    private static native int getUpdateOutputSize(long ref, int len);

    private static native int getOutputSize(long ref, int len);

    public static native byte[] getMac(long ref);

    /**
     * Set blocks remaining but only to a lesser value and only if the transformation has processed no data.
     * Functionality limited to within the module only.
     *
     * @param value the step value.
     */
    void setBlocksRemainingDown(long value)
    {
        setBlocksRemainingDown(refWrapper.getReference(), value);
    }

    // Set the blocks remaining, but only to a lesser value.
    // This is intended for testing only and will throw from the native side if the
    // transformation has processed any data.
    private native void setBlocksRemainingDown(long nativeRef, long value);


    private static class GCMRefWrapper
            extends NativeReference
    {
        public GCMRefWrapper(long reference)
        {
            super(reference);
        }

        @Override
        public Runnable createAction()
        {
            return new Disposer(reference);
        }

    }


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
            AESNativeGCM.dispose(reference);
        }
    }

    @Override
    public String toString()
    {
        if (lastKey != null)
        {
            return "GCM[Native](AES[Native](" + (lastKey.length * 8) + "))";
        }
        return "GCM[Native](AES[Native](not initialized))";
    }

    private static byte[] K = Hex.decode("feffe9928665731c6d6a8f9467308308");
    private static byte[] P = Hex.decode("d9313225f88406e5a55909c5aff5269a"
            + "86a7a9531534f7da2e4c303d8a318a72"
            + "1c3c0c95956809532fcf0e2449a6b525"
            + "b16aedf5aa0de657ba637b39");
    private static byte[] A = Hex.decode("feedfacedeadbeeffeedfacedeadbeef"
            + "abaddad2");
    private static byte[] IV = Hex.decode("cafebabefacedbaddecaf888");
    private static byte[] C = Hex.decode("42831ec2217774244b7221b784d0d49c"
            + "e3aa212f2c02a4e035c17e2329aca12e"
            + "21d514b25466931c7d8f6a5aac84aa05"
            + "1ba30b396a0aac973d58e091");
    private static byte[] T = Hex.decode("5bc94fbc3221a5db94fae95ae7121a47");
    private static TestTrigger trigger = new TestTrigger();

    static AESNativeGCM newInstance()
    {
        AESNativeGCM engine = new AESNativeGCM();
        if (trigger.triggerTest())
        {
            // FSM_STATE:5.AES.8,"NATIVE GCM GMAC GENERATE VERIFY KAT","The module is performing Native GCM/GMAC generate and verify KAT self-test"
            // FSM_TRANS:5.AES.8.0,"CONDITIONAL TEST","NATIVE GCM GMAC GENERATE VERIFY KAT","Invoke Native GCM Generate/Verify KAT self-test"
            return SelfTestExecutor.validate(FipsAES.GCM.getAlgorithm(), engine, new BasicKatTest<AESNativeGCM>()
            {
                @Override
                public boolean hasTestPassed(AESNativeGCM engine)
                        throws Exception
                {
                    AEADBlockCipher encCipher = engine;

                    CipherParameters params = new org.bouncycastle.crypto.internal.params.AEADParameters(new KeyParameterImpl(K), T.length * 8, IV, A);

                    encCipher.init(true, params);

                    byte[] enc = new byte[encCipher.getOutputSize(P.length)];

                    int len = encCipher.processBytes(P, 0, P.length, enc, 0);
                    len += encCipher.doFinal(enc, len);

                    if (enc.length != len)
                    {
                        return false;
                    }

                    byte[] mac = encCipher.getMac();

                    byte[] data = new byte[P.length];
                    System.arraycopy(enc, 0, data, 0, data.length);
                    byte[] tail = new byte[enc.length - P.length];
                    System.arraycopy(enc, P.length, tail, 0, tail.length);

                    if (!Arrays.areEqual(C, data))
                    {
                        return false;
                    }

                    if (!Arrays.areEqual(T, mac))
                    {
                        return false;
                    }

                    if (!Arrays.areEqual(T, tail))
                    {
                        return false;
                    }

                    AEADBlockCipher decCipher = engine;

                    decCipher.init(false, params);

                    byte[] dec = new byte[decCipher.getOutputSize(enc.length)];

                    len = decCipher.processBytes(enc, 0, enc.length, dec, 0);
                    decCipher.doFinal(dec, len);
                    mac = decCipher.getMac();

                    data = new byte[C.length];
                    System.arraycopy(dec, 0, data, 0, data.length);

                    return Arrays.areEqual(P, data) && Arrays.areEqual(T, mac);
                }
            });
            // FSM_TRANS:5.AES.8.1,"NATIVE GCM GMAC GENERATE VERIFY KAT","CONDITIONAL TEST","Native GCM Generate/Verify KAT self-test successful completion"
            // FSM_TRANS:5.AES.8.2,"NATIVE GCM GMAC GENERATE VERIFY KAT","SOFT ERROR","Native GCM Generate/Verify KAT self-test failed"
        }

        return engine;
    }
}
