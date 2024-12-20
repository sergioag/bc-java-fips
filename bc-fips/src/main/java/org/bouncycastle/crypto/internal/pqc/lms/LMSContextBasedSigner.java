/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.internal.pqc.lms;

public interface LMSContextBasedSigner
{
    LMSContext generateLMSContext();

    byte[] generateSignature(LMSContext context);
}
