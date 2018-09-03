package edu.stanford.cs.crypto.efficientct.algebra;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECMultiplier;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public class C0C0Group extends BouncyCastleCurve {

    public static final BigInteger P = new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617");
    public static final BigInteger ORDER = new BigInteger("2736030358979909402780800718157159386074658810754251464600343418943805806723");
    private static final BigInteger A = new BigInteger("7296080957279758407415468581752425029516121466805344781232734728853232254332");
    private static final BigInteger B = new BigInteger("1621351323839946312758993018167205562114693659290076618051718980123722470666");
    private static final BigInteger COFACTOR = BigInteger.valueOf(8);
    private static final ECCurve curve = new ECCurve.Fp(P, A, B, ORDER, COFACTOR);
    private static final ECFieldElement a = curve.fromBigInteger(A);
    private static final ECFieldElement b = curve.fromBigInteger(B);

    public static final ECPoint G = curve.validatePoint(new BigInteger("7296080957279758407415468581752425029516121466805344781232734728858602874187"), new BigInteger("5854969154019084038134685408453962516899849177257040453511959087213437462470"));


    public C0C0Group() {
        super(curve, G);
    }

    @Override
    public BouncyCastleECPoint mapInto(BigInteger seed) {
        seed = seed.mod(P);

        ECFieldElement y;
        seed = seed.subtract(BigInteger.ONE);
        BouncyCastleECPoint point;
        do {
            seed = seed.add(BigInteger.ONE);
            ECFieldElement x = curve.fromBigInteger(seed);

            ECFieldElement rhs = x.square().add(a).multiply(x).add(b);

            y = rhs.sqrt();
            if (y != null) {

                point = new BouncyCastleECPoint(curve.createPoint(x.toBigInteger(), y.toBigInteger()));

                 point = point.multiply(COFACTOR);
                if (!point.equals(zero())) {
                    break;
                }
            }
        } while (true);

        return point;
    }

    public String toMontgomery(BouncyCastleECPoint point) {
        ECFieldElement montA = curve.fromBigInteger(new BigInteger("126932"));
        ECPoint normalizedPoint = point.getPoint().normalize();
        ECFieldElement montX = normalizedPoint.getXCoord().subtract(montA.divide(curve.fromBigInteger(BigInteger.valueOf(3))));

        return "[0x" + montX + " , 0x" + normalizedPoint.getYCoord() + "]";

    }

}
