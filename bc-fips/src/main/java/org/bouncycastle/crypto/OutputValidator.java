package org.bouncycastle.crypto;

/**
 * Base interface for an output validator which can be used to verify a data stream.
 *
 * @param <T> the parameters type for the verifier.
 */
public interface OutputValidator<T extends Parameters>
{
    /**
     * Return the parameters for this output verifier.
     *
     * @return the verifier's parameters.
     */
    T getParameters();

    /**
     * Returns a stream that will accept data for the purpose of verifying a previously calculated signature.
     * Use org.bouncycastle.util.io.TeeOutputStream if you want to accumulate the data on the fly as well.
     *
     * @return an UpdateOutputStream
     */
    UpdateOutputStream getValidatingStream();

    /**
     * Return true if the data written to the validating stream validates against the underlying implementation.
     *
     * @return true if the data validates, false otherwise.
     */
    boolean isValidated();
}
