package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.PasswordBasedDeriver;
import org.bouncycastle.crypto.PasswordConverter;
import org.bouncycastle.crypto.internal.PBEParametersGenerator;
import org.bouncycastle.crypto.internal.test.BasicKatTest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/**
 * Source class for FIPS approved implementations of Password-Based Key Derivation algorithms.
 */
public final class FipsPBKD
{
    /**
     * Algorithm ID for PBKDF2 (PKCS#5 scheme 2)
     */
    private static final FipsAlgorithm ALGORITHM_PBKDF2 = new FipsAlgorithm("PBKDF2");

    static
    {
        // FSM_STATE:5.PBKDF.0,"PBKDF GENERATE KAT","The module is performing PBKDF generate KAT self-test"
        // FSM_TRANS:5.PBKDF.0.0,"CONDITIONAL TEST","PBKDF GENERATE KAT","Invoke PBKDF Generate KAT self-test"
        Parameters parameters = new ParametersBuilder().using(FipsSHS.Algorithm.SHA256_HMAC, Strings.toByteArray("Legion of the Bouncy Castle"))
            .withIterationCount(2048).withSalt(Hex.decode("0102030405060708090a0b0c0e0d0e0f"));
        PKCS5S2ParametersGenerator<Parameters> engine = new PKCS5S2ParametersGenerator<Parameters>(
            parameters,
            FipsSHS.createHMac(FipsSHS.Algorithm.SHA256_HMAC));
        // As per IG 10.3.A
        SelfTestExecutor.validate(ALGORITHM_PBKDF2, engine,
            new PbkdfTest<PKCS5S2ParametersGenerator<Parameters>>(parameters, Hex.decode("fb18073c0bc900343ad8280821938255")));
        // FSM_TRANS:5.PBKDF.0.1,"PBKDF GENERATE KAT","CONDITIONAL TEST","PBKDF Generate KAT self-test successful completion"
        // FSM_TRANS:5.PBKDF.0.2,"PBKDF GENERATE KAT","SOFT ERROR","PBKDF Generate KAT self-test failed"
    }

    /**
     * PBKDF2  algorithm parameter source - default PRF is HMAC(SHA-1)
     */
    public static final ParametersBuilder PBKDF2 = new ParametersBuilder();

    private FipsPBKD()
    {

    }

    /**
     * Initial builder for PBKDF2 parameters.
     */
    public static final class ParametersBuilder
        extends FipsParameters
    {
        ParametersBuilder()
        {
            super(ALGORITHM_PBKDF2);
        }

        public Parameters using(byte[] password)
        {
            return using(FipsSHS.Algorithm.SHA1_HMAC, password);
        }

        public Parameters using(FipsDigestAlgorithm algorithm, byte[] password)
        {
            return new Parameters(algorithm, null, Arrays.clone(password), 1024, new byte[20]);
        }

        public Parameters using(PasswordConverter converter, char[] password)
        {
            return new Parameters(FipsSHS.Algorithm.SHA1_HMAC, converter, password);
        }

        public Parameters using(FipsDigestAlgorithm algorithm, PasswordConverter converter, char[] password)
        {
            return new Parameters(algorithm, converter, converter.convert(password), 1024, new byte[20]);
        }
    }

    /**
     * PBKD parameters.
     */
    public static final class Parameters
        extends FipsParameters
    {
        private final FipsDigestAlgorithm digestAlgorithm;
        private final PasswordConverter converter;
        private final byte[] password;

        private final byte[] salt;
        private final int iterationCount;

        private Parameters(FipsDigestAlgorithm digestAlgorithm, PasswordConverter converter, byte[] password, int iterationCount, byte[] salt)
        {
            super(ALGORITHM_PBKDF2);
            this.digestAlgorithm = digestAlgorithm;
            this.converter = converter;
            this.password = password;
            this.iterationCount = iterationCount;
            this.salt = salt;

            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                if (salt.length < 16)
                {
                    throw new FipsUnapprovedOperationError("salt must be at least 128 bits");
                }
                if (password.length < 14)
                {
                    throw new FipsUnapprovedOperationError("password must be at least 112 bits");
                }
            }
        }

        private Parameters(FipsDigestAlgorithm algorithm, PasswordConverter converter, char[] password)
        {
            this(algorithm, converter, converter.convert(password), 1024, new byte[20]);
        }

        public Parameters withSalt(byte[] salt)
        {                                                   // need copy of password as zeroize on finalisation
            return new Parameters(digestAlgorithm, converter, getPassword(), iterationCount, Arrays.clone(salt));
        }

        public Parameters withIterationCount(int iterationCount)
        {                                                   // need copy of password as zeroize on finalisation
            return new Parameters(digestAlgorithm, converter, getPassword(), iterationCount, salt);
        }

        synchronized byte[] getPassword()
        {
            return Arrays.clone(password); // to protect against premature finalization
        }

        public FipsDigestAlgorithm getPRF()
        {
            return digestAlgorithm;
        }

        public byte[] getSalt()
        {
            return Arrays.clone(salt);
        }

        public int getIterationCount()
        {
            return iterationCount;
        }

        public PasswordConverter getConverter()
        {
            return converter;
        }

        protected void finalize()
        {
            synchronized (this)
            {
                // explicitly zeroize password on deallocation
                Arrays.fill(password, (byte)0);
            }
        }
    }

    /**
     * Factory for password based key derivation functions that are based on PBKDF2 (PKCS#5 scheme 2).
     */
    public static class DeriverFactory
        extends FipsPasswordBasedDeriverFactory<Parameters>
    {
        public PasswordBasedDeriver<Parameters> createDeriver(final Parameters parameters)
        {
            final PKCS5S2ParametersGenerator<Parameters> gen = new PKCS5S2ParametersGenerator<Parameters>(parameters, FipsSHS.createHMac(parameters.getPRF()));

            gen.init(parameters.getPassword(), parameters.getSalt(), parameters.getIterationCount());

            return new PasswordBasedDeriver<Parameters>()
            {
                public Parameters getParameters()
                {
                    return parameters;
                }

                public byte[] deriveKey(KeyType keyType, int keySizeInBytes)
                {
                    return gen.deriveKey(keyType, keySizeInBytes);
                }

                public byte[][] deriveKeyAndIV(KeyType keyType, int keySizeInBytes, int ivSizeInBytes)
                {
                    return gen.deriveKeyAndIV(keyType, keySizeInBytes, ivSizeInBytes);
                }
            };
        }
    }

    private static class PbkdfTest<T extends PBEParametersGenerator<Parameters>>
        implements BasicKatTest<T>
    {
        private final Parameters params;
        private final byte[] kat;

        PbkdfTest(Parameters params, byte[] kat)
        {
            this.params = params;
            this.kat = kat;
        }

        public boolean hasTestPassed(T generator)
        {
            generator.init(params.password, params.salt, params.iterationCount);

            byte[] result = generator.deriveKey(PasswordBasedDeriver.KeyType.CIPHER, 16);

            return Arrays.areEqual(result, kat);
        }
    }
}
