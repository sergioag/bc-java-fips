package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.util.Arrays;

public class KMACParameterSpec
    implements AlgorithmParameterSpec
{
    private static final byte[] EMPTY_STRING = new byte[0];
    private final int macSizeInBits;
    private final byte[] customizationString;

    public KMACParameterSpec(int macSizeInBits)
    {
        this.macSizeInBits = macSizeInBits;
        this.customizationString = EMPTY_STRING;
    }

    public KMACParameterSpec(int macSizeInBits, byte[] customizationString)
    {
        this.macSizeInBits = macSizeInBits;
        this.customizationString = Arrays.clone(customizationString);
    }

    public int getMacSizeInBits()
    {
        return macSizeInBits;
    }

    public byte[] getCustomizationString()
    {
        return customizationString;
    }
}
