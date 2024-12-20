package org.bouncycastle.jcajce.spec;

import org.bouncycastle.crypto.general.LMS;

public class LMOtsParameters
{
    public static final LMOtsParameters sha256_n32_w1 = new LMOtsParameters(LMS.sha256_n32_w1);
    public static final LMOtsParameters sha256_n32_w2 = new LMOtsParameters(LMS.sha256_n32_w2);
    public static final LMOtsParameters sha256_n32_w4 = new LMOtsParameters(LMS.sha256_n32_w4);
    public static final LMOtsParameters sha256_n32_w8 = new LMOtsParameters(LMS.sha256_n32_w8);

    final LMS.OTSParameters otsParameters;

    LMOtsParameters(LMS.OTSParameters otsParameters)
    {
        this.otsParameters = otsParameters;
    }
}
