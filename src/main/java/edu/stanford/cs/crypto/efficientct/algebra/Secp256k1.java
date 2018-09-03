package edu.stanford.cs.crypto.efficientct.algebra;

import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP256K1FieldElement;

import java.math.BigInteger;

public class Secp256k1 extends BouncyCastleCurve {
    public Secp256k1() {
        super(new SecP256K1Curve(), CustomNamedCurves.getByName("secp256k1").getG());
    }

    @Override
    public BouncyCastleECPoint mapInto(BigInteger seed) {


        ECPoint point = null;
        boolean success = false;
        do {
            ECFieldElement x = new SecP256K1FieldElement(seed.mod(groupOrder()));

            ECFieldElement rhs = x.square().multiply(x.add(curve.getA())).add(curve.getB());

            ECFieldElement y = rhs.sqrt();
            if (y != null) {
                point = curve.validatePoint(x.toBigInteger(), y.toBigInteger());

                success = true;
            } else {
                seed = seed.add(BigInteger.ONE);
            }
        } while (!success);
        return new BouncyCastleECPoint(point);
    }
}
