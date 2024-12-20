/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.internal.pqc.lms;

public interface LMSContextBasedVerifier
{
    LMSContext generateLMSContext(byte[] signature);

    boolean verify(LMSContext context);
}
