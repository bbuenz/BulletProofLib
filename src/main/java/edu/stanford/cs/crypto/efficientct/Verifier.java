package edu.stanford.cs.crypto.efficientct;

import java.util.Objects;

/**
 * Created by buenz on 6/29/17.
 */
public interface Verifier<PP, I, P> {
    void verify(PP params, I input, P proof) throws VerificationFailedException;
     default void equal(Object l,Object r,String message) throws VerificationFailedException{
        if(!Objects.equals(l,r)){
           throw new VerificationFailedException(String.format(message,l,r));
        }
    }
}
