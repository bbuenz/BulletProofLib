package edu.stanford.cs.crypto.efficientct.linearalgebra;

import cyclops.collections.immutable.VectorX;
import cyclops.function.Monoid;
import edu.stanford.cs.crypto.efficientct.util.ECConstants;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

/**
 * Created by buenz on 7/2/17.
 */
public class PeddersenBase extends GeneratorVector {
    private static final Monoid<ECPoint> ECPOINT_SUM = Monoid.of(ECConstants.INFINITY, ECPoint::add);
    public final ECPoint g;
    public final ECPoint h;

    public PeddersenBase(ECPoint g, ECPoint h) {
        super(VectorX.of(g, h));
        this.g = g;
        this.h = h;

    }

    public ECPoint commit(BigInteger x, BigInteger r) {
        return g.multiply(x).add(h.multiply(r));
    }

}
