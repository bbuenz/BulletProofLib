package edu.stanford.cs.crypto.efficientct.rangeproof;

import java.math.BigInteger;

/**
 * Created by buenz on 7/1/17.
 */
public class RangeProofWitness {
    private final BigInteger number;

    private final BigInteger randomness;

    public RangeProofWitness(BigInteger number, BigInteger randomness) {
        this.number = number;
        this.randomness = randomness;
    }

    public BigInteger getNumber() {
        return number;
    }

    public BigInteger getRandomness() {
        return randomness;
    }

}
