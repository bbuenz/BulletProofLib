package edu.stanford.cs.crypto.efficientct.circuit.groups;

import java.math.BigInteger;

public interface Group<T extends GroupElement<T>> {
    T hashInto(BigInteger seed);
    T generator();
    BigInteger groupOrder();
    T zero();
}
