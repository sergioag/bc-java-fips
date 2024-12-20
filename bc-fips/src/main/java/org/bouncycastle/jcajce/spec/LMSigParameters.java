package org.bouncycastle.jcajce.spec;

import org.bouncycastle.crypto.general.LMS;

public class LMSigParameters
{
    public static final LMSigParameters lms_sha256_n32_h5 = new LMSigParameters(LMS.lms_sha256_n32_h5);
    public static final LMSigParameters lms_sha256_n32_h10 = new LMSigParameters(LMS.lms_sha256_n32_h5);
    public static final LMSigParameters lms_sha256_n32_h15 = new LMSigParameters(LMS.lms_sha256_n32_h5);
    public static final LMSigParameters lms_sha256_n32_h20 = new LMSigParameters(LMS.lms_sha256_n32_h5);
    public static final LMSigParameters lms_sha256_n32_h25 = new LMSigParameters(LMS.lms_sha256_n32_h5);

    final LMS.KeyParameters keyParameters;

    LMSigParameters(LMS.KeyParameters keyParameters)
    {
        this.keyParameters = keyParameters;
    }
}
