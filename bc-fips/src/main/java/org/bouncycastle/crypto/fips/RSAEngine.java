package org.bouncycastle.crypto.fips;

import java.math.BigInteger;

import org.bouncycastle.crypto.internal.CipherParameters;

/**
 * Basic unblinded RSA engine implementation.
 * Used to abstract away calls to native backed RSA and Java RSA
 */
public interface RSAEngine
{
    int getInputBlockSize();

    int getOutputBlockSize();

    BigInteger convertInput(byte[] in, int inOff, int inLen);

    BigInteger processBlock(BigInteger blindedInput);

    byte[] convertOutput(BigInteger result);

    void init(boolean forEncryption, CipherParameters param);
}
