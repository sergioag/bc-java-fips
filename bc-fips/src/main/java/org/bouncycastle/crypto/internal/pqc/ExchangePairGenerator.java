/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.internal.pqc;

import org.bouncycastle.crypto.internal.params.AsymmetricKeyParameter;

/**
 * Interface for NewHope style key material exchange generators.
 */
public interface ExchangePairGenerator
{
    /**
     * Generate an exchange pair based on the sender public key.
     *
     * @param senderPublicKey the public key of the exchange initiator.
     * @return An ExchangePair derived from the sender public key.
     * @deprecated use generateExchange
     */
    ExchangePair GenerateExchange(AsymmetricKeyParameter senderPublicKey);

    /**
     * Generate an exchange pair based on the sender public key.
     *
     * @param senderPublicKey the public key of the exchange initiator.
     * @return An ExchangePair derived from the sender public key.
     */
    ExchangePair generateExchange(AsymmetricKeyParameter senderPublicKey);
}
