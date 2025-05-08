package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.EntropySource;

class DRBGPseudoRandom
    implements DRBG
{
    private final FipsAlgorithm algorithm;
    private final DRBGProvider drbgProvider;
    private final EntropySource entropySource;

    private DRBG drbg;
    private int reseedTestThreshold = 0;

    DRBGPseudoRandom(FipsAlgorithm algorithm, EntropySource entropySource, DRBGProvider drbgProvider)
    {
        this.algorithm = algorithm;
        this.entropySource = new ContinuousTestingEntropySource(entropySource);
        this.drbgProvider = drbgProvider;
    }

    /**
     * Return the block size of the underlying DRBG
     *
     * @return number of bits produced each cycle.
     */
    public int getBlockSize()
    {
        synchronized (this)
        {
            lazyInitDRBG();

            return drbg.getBlockSize();
        }
    }

    public int getSecurityStrength()
    {
        synchronized (this)
        {
            lazyInitDRBG();

            return drbg.getSecurityStrength();
        }
    }

    /**
     * Return the personalization string used to create the DRBG.
     *
     * @return the the personalization string used to create the DRBG.
     */
    public byte[] getPersonalizationString()
    {
        synchronized (this)
        {
            lazyInitDRBG();

            return drbg.getPersonalizationString();
        }
    }

    private void lazyInitDRBG()
    {
        if (drbg == null)
        {
            drbg = drbgProvider.get(entropySource);
            // FSM_TRANS:5.7, "CONDITIONAL TEST", "DRBG HEALTH CHECKS", "Invoke DRBG Health Check"
            SelfTestExecutor.validate(algorithm, drbg.createSelfTest(algorithm));   // instance health test
            // FSM_TRANS:5.8, "DRBG HEALTH CHECKS", "CONDITIONAL TEST", "DRBG Health Check successful"
            // FSM_TRANS:5.9, "DRBG HEALTH CHECKS", "SOFT ERROR", "DRBG Health Check failed"
        }
    }

    public int generate(byte[] output, byte[] additionalInput, boolean predictionResistant)
    {
        synchronized (this)
        {
            lazyInitDRBG();

            // if predictionResistant a reseed will be performed at the start of generate.
            if (predictionResistant)
            {
                if (triggerReseedTest())
                {
                    // FSM_STATE:5.7, "DRBG RESEED HEALTH CHECKS", "The module is performing DRBG Reseed Health Check self-test"
                    // FSM_TRANS:5.10, "CONDITIONAL TEST", "DRBG RESEED HEALTH CHECKS", "Invoke DRBG Reseed Health Check"
                    SelfTestExecutor.validate(algorithm, drbg.createReseedSelfTest(algorithm));    // reseed health test
                    // FSM_TRANS:5.11, "DRBG RESEED HEALTH CHECKS", "CONDITIONAL TEST", "DRBG Reseed Health Check successful"
                    // FSM_TRANS:5.12, "DRBG RESEED HEALTH CHECKS", "SOFT ERROR", "DRBG Reseed Health Check failed"
                }
            }

            // check if a reseed is required...
            if (drbg.generate(output, additionalInput, predictionResistant) < 0)
            {
                if (triggerReseedTest())
                {
                    // FSM_STATE:5.6, "DRBG RESEED HEALTH CHECKS", "The module is performing DRBG Reseed Health Check self-test"
                    // FSM_TRANS:5.10, "CONDITIONAL TEST", "DRBG RESEED HEALTH CHECKS", "Invoke DRBG Reseed Health Check"
                    SelfTestExecutor.validate(algorithm, drbg.createReseedSelfTest(algorithm));    // reseed health test
                    // FSM_TRANS:5.11, "DRBG RESEED HEALTH CHECKS", "CONDITIONAL TEST", "DRBG Reseed Health Check successful"
                    // FSM_TRANS:5.12, "DRBG RESEED HEALTH CHECKS", "SOFT ERROR", "DRBG Reseed Health Check failed"
                }

                drbg.reseed(null);
                return drbg.generate(output, additionalInput, predictionResistant);
            }

            return output.length;
        }
    }

    public void reseed(byte[] additionalInput)
    {
        synchronized (this)
        {
            lazyInitDRBG();

            if (triggerReseedTest())
            {
                // FSM_STATE:5.3, "DRBG RESEED HEALTH CHECKS", "The module is performing DRBG Reseed Health Check self-test"
                // FSM_TRANS:5.10, "CONDITIONAL TEST", "DRBG RESEED HEALTH CHECKS", "Invoke DRBG Reseed Health Check"
                SelfTestExecutor.validate(algorithm, drbg.createReseedSelfTest(algorithm));   // reseed health test.
                // FSM_TRANS:5.11, "DRBG RESEED HEALTH CHECKS", "CONDITIONAL TEST", "DRBG Reseed Health Check successful"
                // FSM_TRANS:5.12, "DRBG RESEED HEALTH CHECKS", "SOFT ERROR", "DRBG Reseed Health Check failed"
            }

            drbg.reseed(additionalInput);
        }
    }

    public VariantInternalKatTest createSelfTest(FipsAlgorithm algorithm)
    {
        synchronized (this)
        {
            lazyInitDRBG();

            return drbg.createSelfTest(algorithm);
        }
    }

    public VariantInternalKatTest createReseedSelfTest(FipsAlgorithm algorithm)
    {
        synchronized (this)
        {
            lazyInitDRBG();

            return drbg.createReseedSelfTest(algorithm);
        }
    }

    private boolean triggerReseedTest()
    {
        // test intermittently - allowed by SP 800-90A Section 11.3.4
        // this code will result in reseed always been tested on first use.
        if (reseedTestThreshold == 0 || (reseedTestThreshold > ((System.currentTimeMillis() & 0x3ff) + 50)))
        {
            reseedTestThreshold = 1;
            return true;
        }

        reseedTestThreshold = (reseedTestThreshold + 1) & 0x3ff;
        return false;
    }
}
