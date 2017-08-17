package edu.stanford.cs.crypto.efficientct.circuit;

import edu.stanford.cs.crypto.efficientct.innerproduct.InnerProductProof;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;
import edu.stanford.cs.crypto.efficientct.rangeproof.RangeProof;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

/**
 * Created by buenz on 7/1/17.
 */
public class CircuitProof extends RangeProof {
    private final ECPoint ao;

    public CircuitProof(ECPoint ai, ECPoint ao, ECPoint s, GeneratorVector tCommits, BigInteger tauX, BigInteger mu, BigInteger t, InnerProductProof productProof) {
        super(ai, s, tCommits, tauX, mu, t, productProof);
        this.ao = ao;

    }

    public ECPoint getAo() {
        return ao;
    }
}