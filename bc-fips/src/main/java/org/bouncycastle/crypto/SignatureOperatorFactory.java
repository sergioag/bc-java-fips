package org.bouncycastle.crypto;

/**
 * Interface describing an operator factory that produces signers and verifiers.
 *
 * @param <T> the parameter type for the signers and verifiers we produce.
 */
public interface SignatureOperatorFactory<T extends Parameters>
{
    /**
     * Create a signer which will create signatures against data written to
     * its output stream.
     *
     * @param key the signing key to use.
     * @param parameters the parameters to use to initialize the signer.
     * @return an OutputSigner.
     */
    OutputSigner<T> createSigner(AsymmetricPrivateKey key, T parameters);

    /**
     * Create a verifier which will verify signatures against data written to
     * its output stream.
     *
     * @param key the verification key to use.
     * @param parameters the parameters to use to initialize the verifier.
     * @return an OutputVerifier.
     */
    OutputVerifier<T> createVerifier(AsymmetricPublicKey key, T parameters);

    /**
     * Create a validator which will verify against data written to
     * its output stream against a signature.
     *
     * @param key the verification key to use.
     * @param parameters the parameters to use to initialize the verifier.
     * @param signature the signature that the data is to be validated against.
     * @return an OutputValidator.
     */
    OutputValidator<T> createValidator(AsymmetricPublicKey key, T parameters, byte[] signature)
        throws InvalidSignatureException;
}
