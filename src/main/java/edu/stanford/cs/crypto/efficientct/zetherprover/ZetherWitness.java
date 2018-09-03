package edu.stanford.cs.crypto.efficientct.zetherprover;

import java.math.BigInteger;

public class ZetherWitness {
    private final BigInteger x;
    private final BigInteger r;
    private final BigInteger bTransfer;
    private final BigInteger bDiff;

    public ZetherWitness(BigInteger x, BigInteger r, BigInteger bTransfer, BigInteger bDiff) {
        this.x = x;
        this.r = r;
        this.bTransfer = bTransfer;
        this.bDiff = bDiff;
    }

    public BigInteger getX() {
        return x;
    }

    public BigInteger getR() {
        return r;
    }

    public BigInteger getbTransfer() {
        return bTransfer;
    }

    public BigInteger getbDiff() {
        return bDiff;
    }


}
