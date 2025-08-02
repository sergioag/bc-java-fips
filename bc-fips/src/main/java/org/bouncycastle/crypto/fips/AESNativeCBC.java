package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.internal.CipherParameters;
import org.bouncycastle.crypto.internal.DataLengthException;
import org.bouncycastle.crypto.internal.MultiBlockCipher;
import org.bouncycastle.crypto.internal.params.KeyParameter;
import org.bouncycastle.crypto.internal.params.KeyParameterImpl;
import org.bouncycastle.crypto.internal.params.ParametersWithIV;
import org.bouncycastle.crypto.internal.test.BasicKatTest;
import org.bouncycastle.crypto.util.dispose.NativeDisposer;
import org.bouncycastle.crypto.util.dispose.NativeReference;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

class AESNativeCBC
        implements MultiBlockCipher
{
    // self test data
    private static byte[] key = Hex.decode("000102030405060708090a0b0c0d0e0f");
    private static byte[] enc = Hex.decode("c6a13b37878f5b826f4f8162a1c8d879af9d9926f7dac87192b1c4143ad98958");
    private static TestTrigger trigger = new TestTrigger();

    private CBCRefWrapper referenceWrapper;

    byte[] IV = new byte[16];
    int keySize;

    private boolean encrypting;

    private AESNativeCBC()
    {
         // locked down so that only getInstance can be used.
    }

    @Override
    public void init(boolean forEncryption, CipherParameters params)
            throws IllegalArgumentException
    {
        boolean oldEncrypting = this.encrypting;

        this.encrypting = forEncryption;

        if (params instanceof ParametersWithIV)
        {
            ParametersWithIV ivParam = (ParametersWithIV) params;
            byte[] iv = ivParam.getIV();

            if (iv.length != getBlockSize())
            {
                throw new IllegalArgumentException("initialisation vector must be the same length as block size");
            }

            System.arraycopy(iv, 0, IV, 0, iv.length);

            reset();

            // if null it's an IV changed only.
            if (ivParam.getParameters() != null)
            {
                init((KeyParameter) ivParam.getParameters());
                // cipher.init(encrypting, ivParam.getParameters());
            }
            else
            {
                // The key parameter was null which inidicates that they
                // IV is being changed.

                if (oldEncrypting != encrypting)
                {
                    throw new IllegalArgumentException("cannot change encrypting state without providing key");
                }

                if (referenceWrapper == null)
                {
                    throw new IllegalStateException("IV change attempted but not previously initialized with a key");
                }

                // We need to use the old key because
                // the native layer requires a both key and iv each time.
                init(new KeyParameterImpl(referenceWrapper.oldKey));

            }
        }
        else
        {
            reset();

            // if it's null, key is to be reused.
            if (params != null)
            {
                init((KeyParameter) params);
                // cipher.init(encrypting, params);
            }
            else
            {
                if (oldEncrypting != encrypting)
                {
                    throw new IllegalArgumentException("cannot change encrypting state without providing key.");
                }

                if (referenceWrapper == null)
                {
                    throw new IllegalStateException("IV change attempted but not previously initialized with a key");
                }

                // We need to use the old key because the
                // native layer requires a both key and iv each time.
                init(new KeyParameterImpl(referenceWrapper.oldKey));

            }
        }

    }

    private void init(KeyParameter parameters)
    {

        byte[] key = ((KeyParameter) parameters).getKey();


        switch (key.length)
        {
            case 16:
            case 24:
            case 32:
                break;
            default:
                throw new IllegalArgumentException("key must be only 16,24,or 32 bytes long.");
        }

        referenceWrapper = new CBCRefWrapper(makeNative(key.length, encrypting), Arrays.clone(key));

        if (referenceWrapper.getReference() == 0)
        {
            throw new IllegalStateException("Native CBC native instance returned a null pointer.");
        }

        init(referenceWrapper.getReference(), key, IV);
        keySize = key.length * 8;
    }


    @Override
    public String getAlgorithmName()
    {
        return "AES/CBC";
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

        if (referenceWrapper == null)
        {
            throw new IllegalStateException("not initialized");
        }

        return process(referenceWrapper.getReference(), in, inOff, 1, out, outOff);
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
        return getMultiBlockSize(0);
    }

    @Override
    public int processBlocks(byte[] in, int inOff, int blockCount, byte[] out, int outOff)
            throws DataLengthException, IllegalStateException
    {


        if (referenceWrapper == null)
        {
            throw new IllegalStateException("not initialized");
        }

        return process(referenceWrapper.getReference(), in, inOff, blockCount, out, outOff);
    }

    private static native int process(long ref, byte[] in, int inOff, int blockCount, byte[] out, int outOff);

    private static native int getMultiBlockSize(long ref);

    private static native int getBlockSize(long ref);

    static native long makeNative(int keyLen, boolean encryption);

    static native void init(long nativeRef, byte[] key, byte[] iv);

    static native void dispose(long ref);

    private static native void reset(long nativeRef);
    
    private static class Disposer
            extends NativeDisposer
    {
        private final byte[] oldKey;

        Disposer(long ref, byte[] oldKey)
        {
            super(ref);
            this.oldKey = oldKey;
        }

        @Override
        protected void dispose(long reference)
        {
            Arrays.clear(this.oldKey);
            AESNativeCBC.dispose(reference);
        }
    }

    private class CBCRefWrapper
            extends NativeReference
    {
        private final byte[] oldKey;

        public CBCRefWrapper(long reference, byte[] oldKey)
        {
            super(reference);
            this.oldKey = oldKey;
        }

        @Override
        public Runnable createAction()
        {
            return new Disposer(reference, this.oldKey);
        }
    }

    @Override
    public String toString()
    {
        return "CBC[Native](AES[Native](" + keySize + ")";
    }

    static AESNativeCBC newInstance()
    {
        AESNativeCBC engine = new AESNativeCBC();
        if (trigger.triggerTest())
        {
            // FSM_STATE:5.AES.5,"AES ENCRYPT DECRYPT KAT","The module is performing Native AES CBC encrypt and decrypt KAT self-test"
            // FSM_TRANS:5.AES.5.0,"CONDITIONAL TEST","NATIVE AES CBC ENCRYPT DECRYPT KAT","Invoke Native AES CBC Encrypt/Decrypt KAT self-test"
            return SelfTestExecutor.validate(FipsAES.CBC.getAlgorithm(), engine, new BasicKatTest<AESNativeCBC>()
            {
                @Override
                public boolean hasTestPassed(AESNativeCBC cbcCipher)
                    throws Exception
                {
                    byte[] data = new byte[32];
                    byte[] buf = new byte[32];
                    byte[] iv = new byte[16];

                    cbcCipher.init(true, new ParametersWithIV(new KeyParameterImpl(key), iv));

                    cbcCipher.processBlocks(data, 0, 2, buf, 0);

                    if (!Arrays.areEqual(enc, buf))
                    {
                        return false;
                    }

                    cbcCipher.init(false, new ParametersWithIV(new KeyParameterImpl(key), iv));

                    cbcCipher.processBlocks(enc, 0, 2, buf, 0);

                    return Arrays.areEqual(data, buf);
                }
            });
            // FSM_TRANS:5.AES.5.1,"NATIVE AES CBC ENCRYPT DECRYPT KAT","CONDITIONAL TEST","Native AES CBC Encrypt / Decrypt KAT self-test successful completion"
            // FSM_TRANS:5.AES.5.2,"NATIVE AES CBC ENCRYPT DECRYPT KAT","SOFT ERROR","Native AES CBC Encrypt / Decrypt KAT self-test failed"
        }

        return engine;
    }
}
