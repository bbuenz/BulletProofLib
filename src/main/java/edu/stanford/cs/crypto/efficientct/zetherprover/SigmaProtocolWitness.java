package edu.stanford.cs.crypto.efficientct.zetherprover;

import java.math.BigInteger;

public class SigmaProtocolWitness {
    private final BigInteger x;
    private final BigInteger r;

    public SigmaProtocolWitness(BigInteger x, BigInteger r) {
        this.x = x;
        this.r = r;
    }

    public BigInteger getX() {
        return x;
    }

    public BigInteger getR() {
        return r;
    }


}
