package edu.stanford.cs.crypto.efficientct.algebra;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public abstract class BouncyCastleCurve implements Group<BouncyCastleECPoint> {
    protected final ECCurve curve;
    private final BouncyCastleECPoint generator;

    public BouncyCastleCurve(ECCurve curve, ECPoint generator) {
        this(curve, new BouncyCastleECPoint(generator));
    }

    public BouncyCastleCurve(ECCurve curve, BouncyCastleECPoint generator) {
        this.curve = curve;
        this.generator = generator;
    }


    @Override
    public BouncyCastleECPoint generator() {
        return generator;
    }

    @Override
    public BigInteger groupOrder() {
        return curve.getOrder();
    }

    @Override
    public BouncyCastleECPoint zero() {
        return new BouncyCastleECPoint(curve.getInfinity());
    }

    public ECCurve getCurve() {
        return curve;
    }
}
