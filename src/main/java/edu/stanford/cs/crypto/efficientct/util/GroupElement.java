package edu.stanford.cs.crypto.efficientct.util;

import java.math.BigInteger;

public interface GroupElement<T extends GroupElement<T>> {
    GroupElement<T> add (GroupElement<T> other);
    GroupElement<T> multiply(BigInteger exp);
}
