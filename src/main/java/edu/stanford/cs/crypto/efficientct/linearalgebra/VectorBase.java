package edu.stanford.cs.crypto.efficientct.linearalgebra;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

/**
 * Created by buenz on 7/2/17.
 */
public class VectorBase {
    private final GeneratorVector gs;
    private final GeneratorVector hs;
    private final ECPoint h;

    public VectorBase(GeneratorVector gs, GeneratorVector hs, ECPoint h) {
        this.gs = gs;
        this.hs = hs;
        this.h = h;
    }
    public ECPoint commit(Iterable<BigInteger> gExp, BigInteger blinding) {
        return gs.commit(gExp).add(h.multiply(blinding));

    }

    public ECPoint commit(Iterable<BigInteger> gExp, Iterable<BigInteger> hExp, BigInteger blinding) {
        return gs.commit(gExp).add(hs.commit(hExp)).add(h.multiply(blinding));

    }

    public GeneratorVector getGs() {
        return gs;
    }

    public GeneratorVector getHs() {
        return hs;
    }

    public ECPoint getH() {
        return h;
    }


    @Override
    public String toString() {
        return String.format("[gs:%s,hs:%s,h:%s]",gs,hs,h);
    }
}
