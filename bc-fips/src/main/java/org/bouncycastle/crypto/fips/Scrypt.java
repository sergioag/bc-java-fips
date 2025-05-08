package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.KDFCalculator;
import org.bouncycastle.crypto.KDFOperatorFactory;
import org.bouncycastle.crypto.PasswordConverter;
import org.bouncycastle.util.Arrays;

/**
 * Source class for scrypt utility KDF, an augmentation of the PBKDF2 PBE algorithm which incorporates a memory-hard component.
 * <p>
 * Scrypt was created by Colin Percival and is specified in <a href="https://tools.ietf.org/html/rfc7914">
 * RFC 7914 - The scrypt Password-Based Key Derivation Function</a>
 */
public final class Scrypt
{
    private Scrypt()
    {
    }

    public static final ParametersBuilder ALGORITHM = new ParametersBuilder(new FipsAlgorithm("scrypt"));

    /**
     * Parameters builder for the scrypt key derivation function.
     */
    public static final class ParametersBuilder
        extends FipsParameters
    {
        ParametersBuilder(FipsAlgorithm algorithm)
        {
            super(algorithm);
        }

        /**
         * Generate a key using the scrypt key derivation function.
         *
         * @param salt the salt to use for this invocation.
         * @param n    CPU/Memory cost parameter. Must be larger than 1, a power of 2 and less than
         *             <code>2^(128 * r / 8)</code>.
         * @param r    the block size, must be &gt;= 1.
         * @param p    Parallelization parameter. Must be a positive integer less than or equal to
         *             <code>Integer.MAX_VALUE / (128 * r * 8)</code>.
         * @param seed the value feed into the PBKDF2 function.
         * @return the generated key.
         */
        public Parameters using(byte[] salt, int n, int r, int p, byte[] seed)
        {
            return new Parameters(n, Arrays.clone(seed), r, p, Arrays.clone(salt));
        }

        /**
         * Generate a key using the scrypt key derivation function.
         *
         * @param salt      the salt to use for this invocation.
         * @param n         CPU/Memory cost parameter. Must be larger than 1, a power of 2 and less than
         *                  <code>2^(128 * r / 8)</code>.
         * @param r         the block size, must be &gt;= 1.
         * @param p         Parallelization parameter. Must be a positive integer less than or equal to
         *                  <code>Integer.MAX_VALUE / (128 * r * 8)</code>.
         * @param converter a converter to turn the password characters into the byte array for the seed.
         * @param password  a character string to use as a seed.
         * @return the generated key.
         */
        public Parameters using(byte[] salt, int n, int r, int p, PasswordConverter converter, char[] password)
        {
            return new Parameters(n, converter.convert(password), r, p, Arrays.clone(salt));
        }
    }

    /**
     * Parameters for the scrypt key derivation function.
     */
    public static final class Parameters
        extends FipsParameters
    {
        final int n;
        final int r;
        final int p;
        final byte[] salt;
        final byte[] seed;

        private Parameters(int n, byte[] seed, int r, int p, byte[] salt)
        {
            super(ALGORITHM.getAlgorithm());

            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                if (salt.length < 16)
                {
                    throw new FipsUnapprovedOperationError("salt must be at least 128 bits");
                }
                if (seed.length < 14)
                {
                    throw new FipsUnapprovedOperationError("password must be at least 112 bits");
                }
            }

            this.seed = seed;
            this.n = n;
            this.r = r;
            this.p = p;
            this.salt = salt;
        }
    }

    /**
     * Factory for scrypt KDFs.
     */
    public static final class KDFFactory
        implements KDFOperatorFactory<Parameters>
    {
        public KDFCalculator<Parameters> createKDFCalculator(final Parameters params)
        {
            return new KDFCalculator<Parameters>()
            {
                public Parameters getParameters()
                {
                    return params;
                }

                public void generateBytes(byte[] out)
                {
                    byte[] tmp = SCryptImpl.generate(params.seed, params.salt, params.n, params.r, params.p, out.length);

                    System.arraycopy(tmp, 0, out, 0, out.length);

                    Arrays.fill(tmp, (byte)0);
                }

                public void generateBytes(byte[] out, int outOff, int len)
                {
                    byte[] tmp = SCryptImpl.generate(params.seed, params.salt, params.n, params.r, params.p, len);

                    System.arraycopy(tmp, 0, out, outOff, len);

                    Arrays.fill(tmp, (byte)0);
                }
            };
        }
    }
}
