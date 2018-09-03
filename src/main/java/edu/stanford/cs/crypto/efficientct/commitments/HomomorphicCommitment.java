package edu.stanford.cs.crypto.efficientct.commitments;

import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;

import java.math.BigInteger;

/**
 * Created by buenz on 7/6/17.
 */
public interface HomomorphicCommitment<C extends HomomorphicCommitment<C>> {
    <C2 extends C> C add(C2 other);

    C times(BigInteger exponent);

    C addConstant(BigInteger constant);


}
