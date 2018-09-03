package edu.stanford.cs.crypto.efficientct.zetherprover;

import edu.stanford.cs.crypto.efficientct.algebra.GroupElement;

import java.math.BigInteger;

public class SigmaProtocolStatement<T extends GroupElement<T>> {
    private final ZetherStatement<T> statement;
    private final T tCommits;
    private final BigInteger t;
    private final BigInteger z;
    private final BigInteger tauX;

    public SigmaProtocolStatement(ZetherStatement<T> statement, T tCommits, BigInteger t, BigInteger tauX, BigInteger z) {
        this.statement = statement;
        this.tCommits = tCommits;
        this.t = t;
        this.tauX = tauX;
        this.z = z;
    }

    public BigInteger getTauX() {
        return tauX;
    }

    public BigInteger getZ() {
        return z;
    }

    public ZetherStatement<T> getStatement() {
        return statement;
    }

    public T gettCommits() {
        return tCommits;
    }

    public BigInteger getT() {
        return t;
    }
}
