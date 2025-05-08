package org.bouncycastle.jcajce.spec;

import org.bouncycastle.crypto.fips.FipsLMS;
import org.bouncycastle.crypto.general.LMS;

public class LMSigParameters
{
    public static final LMSigParameters lms_sha256_n32_h5 = new LMSigParameters(FipsLMS.lms_sha256_n32_h5);
    public static final LMSigParameters lms_sha256_n32_h10 = new LMSigParameters(FipsLMS.lms_sha256_n32_h10);
    public static final LMSigParameters lms_sha256_n32_h15 = new LMSigParameters(FipsLMS.lms_sha256_n32_h15);
    public static final LMSigParameters lms_sha256_n32_h20 = new LMSigParameters(FipsLMS.lms_sha256_n32_h20);
    public static final LMSigParameters lms_sha256_n32_h25 = new LMSigParameters(FipsLMS.lms_sha256_n32_h25);

    public static final LMSigParameters lms_sha256_n24_h5 = new LMSigParameters(FipsLMS.lms_sha256_n24_h5);
    public static final LMSigParameters lms_sha256_n24_h10 = new LMSigParameters(FipsLMS.lms_sha256_n24_h10);
    public static final LMSigParameters lms_sha256_n24_h15 = new LMSigParameters(FipsLMS.lms_sha256_n24_h15);
    public static final LMSigParameters lms_sha256_n24_h20 = new LMSigParameters(FipsLMS.lms_sha256_n24_h20);
    public static final LMSigParameters lms_sha256_n24_h25 = new LMSigParameters(FipsLMS.lms_sha256_n24_h25);

    public static final LMSigParameters lms_shake256_n32_h5 = new LMSigParameters(FipsLMS.lms_shake256_n32_h5);
    public static final LMSigParameters lms_shake256_n32_h10 = new LMSigParameters(FipsLMS.lms_shake256_n32_h10);
    public static final LMSigParameters lms_shake256_n32_h15 = new LMSigParameters(FipsLMS.lms_shake256_n32_h15);
    public static final LMSigParameters lms_shake256_n32_h20 = new LMSigParameters(FipsLMS.lms_shake256_n32_h20);
    public static final LMSigParameters lms_shake256_n32_h25 = new LMSigParameters(FipsLMS.lms_shake256_n32_h25);

    public static final LMSigParameters lms_shake256_n24_h5 = new LMSigParameters(FipsLMS.lms_shake256_n24_h5);
    public static final LMSigParameters lms_shake256_n24_h10 = new LMSigParameters(FipsLMS.lms_shake256_n24_h10);
    public static final LMSigParameters lms_shake256_n24_h15 = new LMSigParameters(FipsLMS.lms_shake256_n24_h15);
    public static final LMSigParameters lms_shake256_n24_h20 = new LMSigParameters(FipsLMS.lms_shake256_n24_h20);
    public static final LMSigParameters lms_shake256_n24_h25 = new LMSigParameters(FipsLMS.lms_shake256_n24_h25);
    
    final FipsLMS.KeyParameters keyParameters;

    LMSigParameters(FipsLMS.KeyParameters keyParameters)
    {
        this.keyParameters = keyParameters;
    }
}
