package edu.stanford.cs.crypto.efficientct.util;

import java.math.BigInteger;

public interface Group<T extends GroupElement<T>> {
    GroupElement<T> hashInto(BigInteger seed);
    GroupElement<T> generator();
    BigInteger groupOrder();
}
