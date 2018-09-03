package edu.stanford.cs.crypto.efficientct.circuit;

import edu.stanford.cs.crypto.efficientct.algebra.GroupElement;
import edu.stanford.cs.crypto.efficientct.innerproduct.InnerProductProof;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;
import edu.stanford.cs.crypto.efficientct.rangeproof.RangeProof;

import java.math.BigInteger;

/**
 * Created by buenz on 7/1/17.
 */
public class CircuitProof<T extends GroupElement<T>> extends RangeProof<T> {
    private final T ao;

    public CircuitProof(T ai, T ao, T s, GeneratorVector<T> tCommits, BigInteger tauX, BigInteger mu, BigInteger t, InnerProductProof<T> productProof) {
        super(ai, s, tCommits, tauX, mu, t, productProof);
        this.ao = ao;

    }

    public T getAo() {
        return ao;
    }
}