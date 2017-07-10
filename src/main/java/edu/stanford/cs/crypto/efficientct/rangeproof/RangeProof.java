package edu.stanford.cs.crypto.efficientct.rangeproof;

import edu.stanford.cs.crypto.efficientct.innerproduct.InnerProductProof;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.List;

/**
 * Created by buenz on 7/1/17.
 */
public class RangeProof {
    private final ECPoint a;
    private final ECPoint s;
    private final GeneratorVector tCommits;
    private final BigInteger tauX;
    private final BigInteger mu;
    private final BigInteger t;
    private final InnerProductProof productProof;

    public RangeProof(ECPoint a, ECPoint s, GeneratorVector tCommits, BigInteger tauX, BigInteger mu, BigInteger t, InnerProductProof productProof) {
        this.a = a;
        this.s = s;
        this.tCommits = tCommits;
        this.tauX = tauX;
        this.mu = mu;
        this.t = t;
        this.productProof = productProof;
    }

    public ECPoint getA() {
        return a;
    }

    public ECPoint getS() {
        return s;
    }


    public BigInteger getTauX() {
        return tauX;
    }

    public BigInteger getMu() {
        return mu;
    }

    public BigInteger getT() {
        return t;
    }

    public InnerProductProof getProductProof() {
        return productProof;
    }

    public GeneratorVector gettCommits() {
        return tCommits;
    }
}
