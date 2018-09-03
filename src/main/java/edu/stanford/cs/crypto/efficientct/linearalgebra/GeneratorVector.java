package edu.stanford.cs.crypto.efficientct.linearalgebra;

import cyclops.collections.immutable.VectorX;
import cyclops.function.Monoid;
import edu.stanford.cs.crypto.efficientct.algebra.Group;
import edu.stanford.cs.crypto.efficientct.algebra.GroupElement;

import java.math.BigInteger;
import java.util.Iterator;
import java.util.stream.Stream;

/**
 * Created by buenz on 7/2/17.
 */
public class GeneratorVector<T extends GroupElement<T>> implements Iterable<T> {
    private final VectorX<T> gs;
    private final Group<T> group;
    private final Monoid<T> ECPOINT_SUM;

    public GeneratorVector(VectorX<T> gs, Group<T> group) {
        this.gs = gs;
        this.group = group;
        ECPOINT_SUM = Monoid.of(group.zero(), T::add);
    }

    private GeneratorVector<T> from(VectorX<T> gs) {
        return new GeneratorVector<>(gs, group);
    }

    public GeneratorVector<T> subVector(int start, int end) {
        return from(gs.subList(start, end));
    }

    public T commit(Iterable<BigInteger> exponents) {

        return gs.zip(exponents, T::multiply).reduce(ECPOINT_SUM);
    }


    public T sum() {
        return gs.reduce(ECPOINT_SUM);
    }

    public GeneratorVector<T> haddamard(Iterable<BigInteger> exponents) {
        return from(gs.zip(exponents, T::multiply));

    }

    public GeneratorVector<T> add(Iterable<T> b) {
        return from(gs.zip(b, T::add));
    }

    public T get(int i) {
        return gs.get(i);
    }

    public int size() {
        return gs.size();
    }

    public Stream<T> stream() {
        return gs.stream();
    }

    public VectorX<T> getVector() {
        return gs;
    }

    @Override
    public String toString() {
        return gs.toString();
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
    public Iterator<T> iterator() {
        return gs.iterator();
    }

    public GeneratorVector<T> plus(T other) {
        return from(gs.plus(other));
    }

    public Group<T> getGroup() {
        return group;
    }

    public static <T extends GroupElement<T>> GeneratorVector<T> from(VectorX<T> gs, Group<T> group) {
        return new GeneratorVector<>(gs, group);
    }
}
