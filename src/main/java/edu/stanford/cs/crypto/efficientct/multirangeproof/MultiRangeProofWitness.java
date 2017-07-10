package edu.stanford.cs.crypto.efficientct.multirangeproof;

import cyclops.collections.immutable.VectorX;

import java.math.BigInteger;

/**
 * Created by buenz on 7/1/17.
 */
public class MultiRangeProofWitness {
    private final VectorX<BigInteger> number;

    private final VectorX<BigInteger> randomness;

    public MultiRangeProofWitness(VectorX<BigInteger> number, VectorX<BigInteger> randomness) {
        this.number = number;
        this.randomness = randomness;
    }

    public VectorX<BigInteger> getNumber() {
        return number;
    }

    public VectorX<BigInteger> getRandomness() {
        return randomness;
    }
}
