package org.bouncycastle.its.jcajce;

import org.bouncycastle.util.Arrays;

import java.security.spec.AlgorithmParameterSpec;

/**
 * Parameter spec for an integrated encryptor KEM, as in IEEE_Std_1609_2
 */
class IESKEMParameterSpec
    implements AlgorithmParameterSpec
{
    private final byte[] recipientInfo;
    private final boolean usePointCompression;


    /**
     * Set the IESKEM parameters.
     *
     * @param recipientInfo recipient data.
     */
    public IESKEMParameterSpec(
        byte[] recipientInfo)
    {
        this(recipientInfo, false);
    }

    /**
     * Set the IESKEM parameters - specifying point compression.
     *
     * @param recipientInfo recipient data.
     * @param usePointCompression use point compression on output (ignored on input).
     */
    public IESKEMParameterSpec(
        byte[] recipientInfo,
        boolean usePointCompression)
    {
        this.recipientInfo = Arrays.clone(recipientInfo);
        this.usePointCompression = usePointCompression;
    }

    public byte[] getRecipientInfo()
    {
        return Arrays.clone(recipientInfo);
    }

    public boolean hasUsePointCompression()
    {
        return usePointCompression;
    }
}