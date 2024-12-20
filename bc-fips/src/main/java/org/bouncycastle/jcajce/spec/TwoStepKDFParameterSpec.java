package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.util.Arrays;

public class TwoStepKDFParameterSpec
    implements AlgorithmParameterSpec
{
    private final byte[] salt;
    private final byte[] info;
    private final KDFMode kdfMode;
    private final int r;
    private final CounterLocation location;
    private final byte[] iv;

    public enum KDFMode
    {
        Counter,
        Feedback,
        DoublePipeline
    }

    public enum CounterLocation
    {
        AfterIterationData,
        AfterFixedInput,
        BeforeIterationData
    }

    public static class Builder
    {
        private final KDFMode kdfMode;
        private final int r;

        private byte[] salt;
        private byte[] info;
        private CounterLocation location;
        private byte[] iv;

        /**
         * Construct parameters for HKDF, specifying both the optional salt and
         * optional info.
         *
         * @param kdfMode the KDF mode to use.
         */
        public Builder(KDFMode kdfMode)
        {
            if (kdfMode == KDFMode.Counter)
            {
                throw new IllegalArgumentException("Counter mode needs to be used with r value");
            }
            this.kdfMode = kdfMode;
            this.r = -1;
        }

        /**
         * Construct parameters for TwoStepKDF using Counter mode, specifying both the optional salt and
         * optional info (default location position of After Iteration Data is used).
         *
         * @param kdfMode the KDF mode to use.
         * @param r the bit length of the counter to use.
         */
        public Builder(KDFMode kdfMode, int r)
        {
            if (r % 8 != 0)
            {
                throw new IllegalArgumentException("r must be a multiple of 8");
            }
            this.kdfMode = kdfMode;
            this.r = r;
            this.location = CounterLocation.AfterIterationData;
        }

        /**
         * Specify the optional salt.
         *
         * @param salt the salt to use, may be null for a salt for hashLen zeros.
         * @return the adjusted
         */
        public Builder withSalt(byte[] salt)
        {
            this.salt = Arrays.clone(salt);

            return this;
        }

        /**
         * Specify the optional fixed info.
         *
         * @param info the info to use, may be null for an info field of zero bytes.
         * @return the adjusted
         */
        public Builder withInfo(byte[] info)
        {
            this.info = Arrays.clone(info);

            return this;
        }

        /**
         * Specify the optional fixed info.
         *
         * @param iv the info to use, may be null for an info field of zero bytes.
         * @return the adjusted
         */
        public Builder withIV(byte[] iv)
        {
            this.iv = Arrays.clone(iv);

            return this;
        }

        /**
         * Specify the counter location.
         *
         * @param location the info to use, may be null for an info field of zero bytes.
         * @return the adjusted
         */
        public Builder withCounterLocation(CounterLocation location)
        {
            if (r < 0)
            {
                throw new IllegalStateException("no counter width specified in constructor");
            }

            this.location = location;

            return this;
        }

        public TwoStepKDFParameterSpec build()
        {
            return new TwoStepKDFParameterSpec(this);
        }
    }

    private TwoStepKDFParameterSpec(Builder builder)
    {
        this.kdfMode = builder.kdfMode;
        this.salt = builder.salt;
        this.info = builder.info;
        this.r = builder.r;
        this.location = builder.location;
        this.iv = builder.iv;
    }

    /**
     * Returns the salt, or null if the salt should be generated as a byte array
     * of HashLen zeros.
     *
     * @return the salt, or null
     */
    public KDFMode getKDFMode()
    {
        return kdfMode;
    }

    /**
     * Returns the salt, or null if the salt should be generated as a byte array
     * of HashLen zeros.
     *
     * @return the salt, or null
     */
    public byte[] getSalt()
    {
        return Arrays.clone(salt);
    }

    /**
     * Returns the info field, which may be empty (null is converted to empty).
     *
     * @return the info field, never null
     */
    public byte[] getInfo()
    {
        return Arrays.clone(info);
    }

    /**
     * Return R, the size in bits of the counter, if one is required.
     *
     * @return size of counter in bits.
     */
    public int getR()
    {
        return r;
    }

    /**
     * Return the counter location
     *
     * @return the counter location.
     */
    public CounterLocation getCounterLocation()
    {
        return location;
    }

    /**
     * Return the optional IV, only used with Feedback Mode.
     *
     * @return the iv;
     */
    public byte[] getIV()
    {
        return iv;
    }
}
