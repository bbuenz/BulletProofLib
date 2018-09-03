package edu.stanford.cs.crypto.efficientct.linearalgebra;

import cyclops.collections.immutable.VectorX;
import cyclops.companion.Monoids;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;

import java.math.BigInteger;
import java.util.Iterator;

/**
 * Created by buenz on 7/2/17.
 */
public class FieldVector implements Iterable<BigInteger> {

    private final VectorX<BigInteger> a;
    private final BigInteger q;

    public FieldVector(VectorX<BigInteger> a, BigInteger q) {
        this.a = a;
        this.q = q;
    }

    private FieldVector from(VectorX<BigInteger> vectorX) {
        return new FieldVector(vectorX, q);
    }


    public static FieldVector from(VectorX<BigInteger> vectorX, BigInteger q) {
        return new FieldVector(vectorX, q);
    }

    public static FieldVector from(Iterable<BigInteger> vectorX, BigInteger q) {
        return new FieldVector(VectorX.fromIterable(vectorX), q);
    }

    public static FieldVector random(int n, BigInteger q) {
        return from(VectorX.generate(n, ProofUtils::randomNumber).materialize(), q);
    }

    /**
     * @param b
     * @return &lt;this,b&gt;
     */
    public BigInteger innerPoduct(Iterable<BigInteger> b) {
        return a.zip(b, BigInteger::multiply).reduce(Monoids.bigIntSum).mod(q);
    }

    /**
     * @param b
     * @return this \circ b
     */
    public FieldVector hadamard(Iterable<BigInteger> b) {
        if (!b.iterator().hasNext()) {
            from(VectorX.empty());
        }
        return from(a.zip(b, BigInteger::multiply).map(bi -> bi.mod(q)));
    }

    /**
     * @param b
     * @return \sum_{i=1}^n b_i \cdot a_i
     */
    public FieldVector vectorMatrixProduct(VectorX<FieldVector> b) {
        if (b.size() != a.size()) {
            throw new IllegalArgumentException("Vectors have to be same size");
        }
        return b.zip(a, FieldVector::times).reduce(FieldVector::add).orElse(from(VectorX.empty()));
    }

    /**
     * @param b
     * @return \sum_{i=1}^n b_i \cdot a_i
     */
    public FieldVector matrixVectorProduct(VectorX<FieldVector> b) {
        if (b.get(0).size() != a.size()) {
            throw new IllegalArgumentException("Vectors have to be same size");
        }
        return from(b.map(this::innerPoduct));
    }

    public FieldVector times(BigInteger b) {

        return from(a.map(b::multiply).map(bi -> bi.mod(q)));
    }

    public FieldVector add(Iterable<BigInteger> b) {
        if (!b.iterator().hasNext()) {
            return this;
        }
        return from(a.zip(b, BigInteger::add).map(bi -> bi.mod(q)));
    }

    public FieldVector add(BigInteger constant) {

        return from(a.map(constant::add).map(bi -> bi.mod(q)));
    }

    public FieldVector subtract(Iterable<BigInteger> b) {
        if (!b.iterator().hasNext()) {
            return this;
        }
        return from(a.zip(b, BigInteger::subtract).map(bi -> bi.mod(q)));
    }

    public BigInteger sum() {
        return a.reduce(Monoids.bigIntSum).mod(q);
    }

    public FieldVector invert() {
        return from(a.map(bi -> bi.modInverse(q)));
    }

    public BigInteger firstValue() {
        return a.firstValue();
    }

    public BigInteger get(int i) {
        return a.get(i);
    }

    public int size() {
        return a.size();
    }

    public FieldVector subVector(int start, int end) {
        return from(a.subList(start, end));
    }

    public VectorX<BigInteger> getVector() {
        return a;
    }

    public FieldVector plus(BigInteger other) {
        return from(a.plus(other));
    }

    public static FieldVector pow(BigInteger k, int n, BigInteger q) {
        return from(VectorX.iterate(n, BigInteger.ONE, k::multiply), q);
    }

    @Override
    public Iterator<BigInteger> iterator() {
        return a.iterator();
    }

    @Override
    public String toString() {
        return a.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        FieldVector that = (FieldVector) o;

        return (a != null ? a.equals(that.a) : that.a == null) && (q != null ? q.equals(that.q) : that.q == null);
    }

    @Override
    public int hashCode() {
        int result = a != null ? a.hashCode() : 0;
        result = 31 * result + (q != null ? q.hashCode() : 0);
        return result;
    }
}
