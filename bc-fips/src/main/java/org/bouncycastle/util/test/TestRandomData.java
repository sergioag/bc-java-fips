package org.bouncycastle.util.test;

import org.bouncycastle.util.encoders.Hex;

/**
 * A fixed secure random designed to return data for someone needing random bytes.
 */
public class TestRandomData
    extends FixedSecureRandom
{
    /**
     * Constructor from a Hex encoding of the data.
     *
     * @param encoding a Hex encoding of the data to be returned.
     */
    public TestRandomData(String encoding)
    {
        super(new FixedSecureRandom.Data(Hex.decode(encoding)));
    }

    /**
     * Constructor from a Hex encoding of the data with a minimum bitLength (padding on the left).
     *
     * @param bitLength the mininum bitLength to pad the data to.
     * @param encoding  a Hex encoding of the data to be included in the padded Data.
     */
    public TestRandomData(int bitLength, String encoding)
    {
        super(new FixedSecureRandom.Data(bitLength, Hex.decode(encoding)));
    }

    /**
     * Constructor from an array of bytes.
     *
     * @param encoding a byte array representing the data to be returned.
     */
    public TestRandomData(byte[] encoding)
    {
        super(new FixedSecureRandom.Data(encoding));
    }

    /**
     * Constructor from an array of bytes with a minimum bitLength (padding on the left).
     * 
     * @param bitLength the mininum bitLength to pad the data to.
     * @param data the data to be included in the padded Data.
     */
    public TestRandomData(int bitLength, byte[] data)
    {
        super(new FixedSecureRandom.Data(bitLength, data));
    }
}
