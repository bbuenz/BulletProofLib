package edu.stanford.cs.crypto.efficientct.innerproduct;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.List;

/**
 * Created by buenz on 6/28/17.
 */
public class InnerProductProof {
    private final List<ECPoint> L;
    private final List<ECPoint> R;
    private final BigInteger a;
    private final BigInteger b;

    public InnerProductProof(List<ECPoint> l, List<ECPoint> r, BigInteger a, BigInteger b) {
        L = l;
        R = r;
        this.a = a;
        this.b = b;
    }

    public List<ECPoint> getL() {
        return L;
    }

    public List<ECPoint> getR() {
        return R;
    }

    public BigInteger getA() {
        return a;
    }

    public BigInteger getB() {
        return b;
    }
}
