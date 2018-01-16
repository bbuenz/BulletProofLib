package edu.stanford.cs.crypto.efficientct.circuit.groups;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public class BN128Group extends BouncyCastleCurve {

    public static final BigInteger P = new BigInteger("21888242871839275222246405745257275088696311157297823662689037894645226208583");
   public static final BigInteger ORDER = new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617");



    private static final ECCurve curve = new ECCurve.Fp(P, BigInteger.ZERO, BigInteger.valueOf(3),ORDER,null);
    public static final ECPoint G = curve.validatePoint(BigInteger.ONE, BigInteger.valueOf(2));

    public BN128Group() {
        super(curve, G);
    }

    @Override
    public BouncyCastleECPoint hashInto(BigInteger seed) {
        seed = seed.mod(P);

        BigInteger y;

        seed = seed.subtract(BigInteger.ONE);
        do {
            seed = seed.add(BigInteger.ONE);
            BigInteger ySquared = seed.pow(3).add(BigInteger.valueOf(3)).mod(P);
            y = ySquared.modPow((P.add(BigInteger.ONE)).divide(BigInteger.valueOf(4)), P);
            if (y.modPow(BigInteger.TWO, P).equals(ySquared)) {
                break;
            }
        } while (true);
        return new BouncyCastleECPoint(curve.validatePoint(seed, y));
    }


}
