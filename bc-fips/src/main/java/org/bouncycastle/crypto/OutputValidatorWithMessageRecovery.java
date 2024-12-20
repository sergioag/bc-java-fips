package org.bouncycastle.crypto;

/**
 * Interface for an output validator that also supports message recovery from the signature.
 *
 * @param <T> the parameters type for the signer.
 */
public interface OutputValidatorWithMessageRecovery<T extends Parameters>
    extends OutputValidator<T>
{
    /**
     * Return the recovered message details found in the signature.
     *
     * @return recovered message details.
     */
    RecoveredMessage getRecoveredMessage();

    /**
     * Update the validator with the recovered message data found in the signature.
     *
     * @throws InvalidSignatureException if the signature cannot be processed.
     */
    void updateWithRecoveredMessage()
        throws InvalidSignatureException;
}
