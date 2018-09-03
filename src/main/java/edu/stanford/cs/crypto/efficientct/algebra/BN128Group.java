package edu.stanford.cs.crypto.efficientct.algebra;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public class BN128Group implements Group<BN128Point> {

    public static final BigInteger P = new BigInteger("21888242871839275222246405745257275088696311157297823662689037894645226208583");
    public static final BigInteger ORDER = new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617");


    private static final ECCurve curve = new ECCurve.Fp(P, BigInteger.ZERO, BigInteger.valueOf(3), ORDER, null);
    public static final ECPoint G = curve.validatePoint(BigInteger.ONE, BigInteger.valueOf(2));
    private static final BN128Point GPoint = new BN128Point(G);

    public BN128Group() {
    }

    @Override
    public BN128Point mapInto(BigInteger seed) {
        seed = seed.mod(P);

        BigInteger y;

        seed = seed.subtract(BigInteger.ONE);
        do {
            seed = seed.add(BigInteger.ONE);
            BigInteger ySquared = seed.pow(3).add(BigInteger.valueOf(3)).mod(P);
            y = ySquared.modPow((P.add(BigInteger.ONE)).divide(BigInteger.valueOf(4)), P);
            if (y.modPow(BigInteger.valueOf(2), P).equals(ySquared)) {
                break;
            }
        } while (true);
        return new BN128Point(curve.validatePoint(seed, y));
    }


    @Override
    public BN128Point generator() {
        return GPoint;
    }

    @Override
    public BigInteger groupOrder() {
        return ORDER;
    }


    @Override
    public BN128Point zero() {
        return new BN128Point(curve.getInfinity());
    }

    public ECCurve getCurve() {
        return curve;
    }


}
