package edu.stanford.cs.crypto.efficientct;

import java.math.BigInteger;
import java.util.Objects;
import java.util.Optional;

/**
 * Created by buenz on 6/29/17.
 */
public interface Verifier<PP, I, P> {
    default void verify(PP params, I input, P proof, BigInteger salt) throws VerificationFailedException {
        verify(params, input, proof, Optional.of(salt));
    }
    default void verify(PP params, I input, P proof) throws VerificationFailedException {
        verify(params, input, proof, Optional.empty());
    }

    void verify(PP params, I input, P proof, Optional<BigInteger> salt) throws VerificationFailedException;

    default void equal(Object l, Object r, String message) throws VerificationFailedException {
        if (!Objects.equals(l, r)) {
            throw new VerificationFailedException(String.format(message, l, r));
        }
    }
}
