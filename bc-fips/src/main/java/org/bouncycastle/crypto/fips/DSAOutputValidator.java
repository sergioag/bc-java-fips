package org.bouncycastle.crypto.fips;

import java.math.BigInteger;

import org.bouncycastle.crypto.InvalidSignatureException;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.internal.DSA;
import org.bouncycastle.crypto.internal.Digest;
import org.bouncycastle.crypto.internal.io.DigestOutputStream;

class DSAOutputValidator<T extends Parameters>
    extends FipsOutputValidator<T>
{
    private final DSA dsa;
    private final Digest digest;
    private final BigInteger[] rs;
    private final T parameter;

    DSAOutputValidator(DSA dsa, Digest digest, T parameter, byte[] signature)
        throws InvalidSignatureException
    {
        this.dsa = dsa;
        this.digest = digest;
        this.parameter = parameter;
        try
        {
            this.rs = DSAOutputVerifier.decode(signature);
        }
        catch (Exception e)
        {
            throw new InvalidSignatureException("Unable to process signature: " + e.getMessage(), e);
        }
    }

    @Override
    public T getParameters()
    {
        return parameter;
    }

    @Override
    public org.bouncycastle.crypto.UpdateOutputStream getValidatingStream()
    {
        return new DigestOutputStream(digest);
    }

    @Override
    public boolean isValidated()
    {
        byte[] m = new byte[digest.getDigestSize()];

        digest.doFinal(m, 0);

        return dsa.verifySignature(m, rs[0], rs[1]);
    }
}
