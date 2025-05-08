package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.internal.*;
import org.bouncycastle.crypto.internal.modes.CFBBlockCipher;
import org.bouncycastle.crypto.internal.modes.SICBlockCipher;
import org.bouncycastle.crypto.internal.params.KeyParameter;
import org.bouncycastle.crypto.internal.params.KeyParameterImpl;
import org.bouncycastle.crypto.internal.params.ParametersWithIV;
import org.bouncycastle.crypto.internal.test.BasicKatTest;
import org.bouncycastle.crypto.util.dispose.NativeDisposer;
import org.bouncycastle.crypto.util.dispose.NativeReference;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

class AESNativeCTR implements StreamCipher, SkippingStreamCipher, MultiBlockCipher
{
    private static byte[] key = Hex.decode("000102030405060708090a0b0c0d0e0f");
    private static byte[] enc = Hex.decode("c6a13b37878f5b826f4f8162a1c8d8797346139595c0b41e497bbde365f42d0a");
    private static TestTrigger trigger = new TestTrigger();

    private CTRRefWrapper referenceWrapper = null;

    private AESNativeCTR()
    {
         // locked down so that only getInstance can be used.
    }

    @Override
    public int getBlockSize()
    {
        return 16;
    }


    @Override
    public int processBlock(byte[] in, int inOff, byte[] out, int outOff) throws DataLengthException, IllegalStateException
    {
        if (referenceWrapper == null)
        {
            throw new IllegalStateException("not initialized");
        }

        return processBytes(referenceWrapper.getReference(), in, inOff, getBlockSize(), out, outOff);

    }

    @Override
    public int getMultiBlockSize()
    {
        return getMultiBlockSize(referenceWrapper.getReference());
    }

    @Override
    public int processBlocks(byte[] in, int inOff, int blockCount, byte[] out, int outOff) throws DataLengthException, IllegalStateException
    {
        int extent = getBlockSize() * blockCount;

        if (referenceWrapper == null)
        {
            throw new IllegalStateException("not initialized");
        }

        return processBytes(referenceWrapper.getReference(), in, inOff, extent, out, outOff);
    }

    @Override
    public long skip(long numberOfBytes)
    {
        if (referenceWrapper == null)
        {
            throw new IllegalStateException("not initialized");
        }
        return skip(referenceWrapper.getReference(), numberOfBytes);
    }

    @Override
    public long seekTo(long position)
    {
        if (referenceWrapper == null)
        {
            throw new IllegalStateException("not initialized");
        }
        return seekTo(referenceWrapper.getReference(), position);
    }

    @Override
    public long getPosition()
    {
        if (referenceWrapper == null)
        {
            throw new IllegalStateException("not initialized");
        }
        return getPosition(referenceWrapper.getReference());
    }


    @Override
    public void init(boolean forEncryption, CipherParameters params) throws IllegalArgumentException
    {
        if (params instanceof ParametersWithIV)
        {
            ParametersWithIV ivParam = (ParametersWithIV) params;
            byte[] iv = ivParam.getIV();

            int blockSize = getBlockSize();

            int maxCounterSize = (8 > blockSize / 2) ? blockSize / 2 : 8;

            if (blockSize - iv.length > maxCounterSize)
            {
                throw new IllegalArgumentException("CTR mode requires IV of at least: " + (blockSize - maxCounterSize) + " bytes.");
            }

            if (referenceWrapper == null)
            {
                referenceWrapper = new CTRRefWrapper(makeNative());
            }

            // if null it's an IV changed only.
            if (ivParam.getParameters() == null)
            {
                init(referenceWrapper.getReference(), null, iv);
            }
            else
            {
                byte[] key = ((KeyParameter) ivParam.getParameters()).getKey();

                switch (key.length)
                {
                    case 16:
                    case 24:
                    case 32:
                        break;
                    default:
                        throw new IllegalArgumentException("invalid key length, key must be 16,24 or 32 bytes");
                }

                init(referenceWrapper.getReference(), key, iv);
            }

            reset();
        }
        else
        {
            throw new IllegalArgumentException("CTR mode requires ParametersWithIV");
        }
    }

    static native long makeNative();

    @Override
    public String getAlgorithmName()
    {
        return "AES/CTR";
    }

    @Override
    public byte returnByte(byte in)
    {
        if (referenceWrapper == null)
        {
            throw new IllegalStateException("not initialized");
        }
        return returnByte(referenceWrapper.getReference(), in);
    }

    @Override
    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff) throws DataLengthException
    {
        if (referenceWrapper == null)
        {
            throw new IllegalStateException("not initialized");
        }

        return processBytes(referenceWrapper.getReference(), in, inOff, len, out, outOff);
    }

    @Override
    public void reset()
    {
        if (referenceWrapper == null)
        {
            return;
        }

        reset(referenceWrapper.getReference());
    }

    private static native long getPosition(long reference);

    private static native int getMultiBlockSize(long ref);

    private static native long skip(long ref, long numberOfByte);

    private static native long seekTo(long ref, long position);

    static native void init(long ref, byte[] key, byte[] iv);

    private static native byte returnByte(long ref, byte b);

    private static native int processBytes(long ref, byte[] in, int inOff, int len, byte[] out, int outOff);

    private static native void reset(long ref);


    native static void dispose(long ref);


    private static class CTRRefWrapper
            extends NativeReference
    {
        public CTRRefWrapper(long reference)
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
            AESNativeCTR.dispose(reference);
        }
    }

    static AESNativeCTR newInstance()
    {
        AESNativeCTR engine = new AESNativeCTR();
        if (trigger.triggerTest())
        {
            // FSM_STATE:5.AES.7,"AES ENCRYPT DECRYPT KAT","The module is performing Native AES CTR encrypt and decrypt KAT self-test"
            // FSM_TRANS:5.AES.7.0,"CONDITIONAL TEST","NATIVE AES CTR ENCRYPT DECRYPT KAT","Invoke Native AES CTR Encrypt/Decrypt KAT self-test"
            return SelfTestExecutor.validate(FipsAES.CTR.getAlgorithm(), engine, new BasicKatTest<AESNativeCTR>()
            {
                @Override
                public boolean hasTestPassed(AESNativeCTR ctrCipher)
                    throws Exception
                {
                    byte[] data = new byte[32];
                    byte[] buf = new byte[32];
                    byte[] iv = new byte[16];

                    ctrCipher.init(true, new ParametersWithIV(new KeyParameterImpl(key), iv));

                    ctrCipher.processBlocks(data, 0, 2, buf, 0);

                    if (!Arrays.areEqual(enc, buf))
                    {
                        return false;
                    }

                    ctrCipher.init(false, new ParametersWithIV(new KeyParameterImpl(key), iv));

                    ctrCipher.processBlocks(enc, 0, 2, buf, 0);

                    return Arrays.areEqual(data, buf);
                }
            });
            // FSM_TRANS:5.AES.7.1,"NATIVE AES CTR ENCRYPT DECRYPT KAT","CONDITIONAL TEST","Native AES CTR Encrypt / Decrypt KAT self-test successful completion"
            // FSM_TRANS:5.AES.7.2,"NATIVE AES CTR ENCRYPT DECRYPT KAT","SOFT ERROR","Native AES CTR Encrypt / Decrypt KAT self-test failed"
        }

        return engine;
    }
}
