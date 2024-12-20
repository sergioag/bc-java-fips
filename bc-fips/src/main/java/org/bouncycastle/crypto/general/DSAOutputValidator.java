package org.bouncycastle.crypto.general;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.crypto.InvalidSignatureException;
import org.bouncycastle.crypto.OutputValidator;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.internal.DSA;
import org.bouncycastle.crypto.internal.Digest;
import org.bouncycastle.crypto.internal.io.DigestOutputStream;

class DSAOutputValidator<T extends Parameters>
    implements OutputValidator<T>
{
    private final DSA dsa;
    private final Digest digest;
    private final T parameter;
    private final boolean reverse;
    private final BigInteger[] rs;

    DSAOutputValidator(DSA dsa, Digest digest, T parameter, byte[] signature)
        throws InvalidSignatureException
    {
        this(dsa, digest, parameter, signature, false);
    }

    DSAOutputValidator(DSA dsa, Digest digest, T parameter, byte[] signature, boolean reverse)
        throws InvalidSignatureException
    {
        this.dsa = dsa;
        this.digest = digest;
        this.parameter = parameter;
        this.reverse = reverse;
        try
        {
            this.rs = DSAOutputVerifier.decode(dsa, signature, reverse);
        }
        catch (IOException e)
        {
            throw new InvalidSignatureException("Unable to process signature: " + e.getMessage(), e);
        }
    }

    public T getParameters()
    {
        return parameter;
    }

    public org.bouncycastle.crypto.UpdateOutputStream getValidatingStream()
    {
        return new DigestOutputStream(digest);
    }

    public boolean isValidated()
    {
        byte[] m = new byte[digest.getDigestSize()];

        digest.doFinal(m, 0);

        return dsa.verifySignature(m, rs[0], rs[1]);
    }
}
