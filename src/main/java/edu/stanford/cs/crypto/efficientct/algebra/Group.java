package edu.stanford.cs.crypto.efficientct.algebra;

import java.math.BigInteger;

public interface Group<T extends GroupElement<T>> {
    T mapInto(BigInteger seed);

    T generator();

    BigInteger groupOrder();

    T zero();
}
