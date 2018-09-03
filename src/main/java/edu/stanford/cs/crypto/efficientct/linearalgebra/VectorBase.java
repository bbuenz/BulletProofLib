package edu.stanford.cs.crypto.efficientct.linearalgebra;

import edu.stanford.cs.crypto.efficientct.algebra.GroupElement;

import java.math.BigInteger;

/**
 * Created by buenz on 7/2/17.
 */
public class VectorBase<T extends GroupElement<T>> {
    private final GeneratorVector<T> gs;
    private final GeneratorVector<T> hs;
    private final T h;

    public VectorBase(GeneratorVector<T> gs, GeneratorVector<T> hs, T h) {
        this.gs = gs;
        this.hs = hs;
        this.h = h;
    }

    public T commit(Iterable<BigInteger> gExp, BigInteger blinding) {
        return gs.commit(gExp).add(h.multiply(blinding));

    }

    public T commit(Iterable<BigInteger> gExp, Iterable<BigInteger> hExp, BigInteger blinding) {
        return gs.commit(gExp).add(hs.commit(hExp)).add(h.multiply(blinding));

    }

    public GeneratorVector<T> getGs() {
        return gs;
    }

    public GeneratorVector<T> getHs() {
        return hs;
    }

    public T getH() {
        return h;
    }


    @Override
    public String toString() {
        return String.format("[gs:%s,hs:%s,h:%s]", gs, hs, h);
    }
}
