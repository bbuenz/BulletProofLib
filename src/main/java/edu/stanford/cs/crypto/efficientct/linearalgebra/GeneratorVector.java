package edu.stanford.cs.crypto.efficientct.linearalgebra;

import cyclops.collections.immutable.VectorX;
import cyclops.function.Monoid;
import edu.stanford.cs.crypto.efficientct.util.ECConstants;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Iterator;
import java.util.stream.Stream;

/**
 * Created by buenz on 7/2/17.
 */
public class GeneratorVector implements Iterable<ECPoint> {
    private final VectorX<ECPoint> gs;
    private static final Monoid<ECPoint> ECPOINT_SUM = Monoid.of(ECConstants.INFINITY, ECPoint::add);

    public GeneratorVector(VectorX<ECPoint> gs) {
        this.gs = gs;
    }

    public static GeneratorVector from(VectorX<ECPoint> gs) {
        return new GeneratorVector(gs);
    }

    public GeneratorVector subVector(int start, int end) {
        return from(gs.subList(start, end));
    }

    public ECPoint commit(Iterable<BigInteger> exponents) {

        return gs.zip(exponents, ECPoint::multiply).reduce(ECPOINT_SUM);
    }


    public ECPoint sum() {
        return gs.reduce(ECPOINT_SUM);
    }

    public GeneratorVector haddamard(Iterable<BigInteger> exponents) {
        return from(gs.zip(exponents, ECPoint::multiply));

    }

    public GeneratorVector add(Iterable<ECPoint> b) {
        return from(gs.zip(b, ECPoint::add));
    }

    public ECPoint get(int i) {
        return gs.get(i);
    }

    public int size() {
        return gs.size();
    }

    public Stream<ECPoint> stream() {
        return gs.stream();
    }

    public VectorX<ECPoint> getVector() {
        return gs;
    }

    @Override
    public String toString() {
        return gs.map(ECPoint::normalize).toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null || !(obj instanceof GeneratorVector)) {
            return false;
        }
        GeneratorVector vector = (GeneratorVector) obj;
        return gs.equals(vector.gs);
    }

    @Override
    public Iterator<ECPoint> iterator() {
        return gs.iterator();
    }

    public GeneratorVector plus(ECPoint other) {
        return from(gs.plus(other));
    }
}
