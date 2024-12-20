package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.util.Arrays;

/**
 * ParameterSpec for EdDSA signature to allow for context and preHash.
 */
public class EdDSASigParameterSpec
    implements AlgorithmParameterSpec
{
    private final boolean preHash;
    private final byte[] context;

    /**
     * Base constructor.
     *
     * @param preHash whether or not the signature is a preHash one.
     */
    public EdDSASigParameterSpec(boolean preHash)
    {
        if (preHash != false)
        {
            throw new IllegalStateException("only false supported at the moment");
        }
        this.preHash = preHash;
        this.context = null;
    }

    /**
     * Base constructor.
     *
     * @param preHash whether or not the signature is a preHash one.
     * @param context context to be added to the signature calculation.
     */
    public EdDSASigParameterSpec(boolean preHash, byte[] context)
    {
        if (preHash != false)
        {
            throw new IllegalStateException("only false supported at the moment");
        }
        if (context.length > 255)
        {
            throw new IllegalStateException("context length > 255");
        }
        this.preHash = preHash;
        this.context = Arrays.clone(context);
    }

    /**
     * Return the context to be used for the signature.
     *
     * @return the signature context.
     */
    public byte[] getContext()
    {
        return Arrays.clone(context);
    }
}
