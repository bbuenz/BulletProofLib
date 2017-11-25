package edu.stanford.cs.crypto.efficientct;

import edu.stanford.cs.crypto.efficientct.circuit.groups.ECBNCurve;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.djb.Curve25519;
import org.bouncycastle.math.ec.custom.djb.Curve25519FieldElement;
import org.junit.Test;

import javax.xml.bind.DatatypeConverter;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

public class Playground {
    @Test
    public void testPlayGround() {
        BigInteger q = new BigInteger("21888242871839275222246405745257275088696311157297823662689037894645226208583");
        ECCurve bnCurve = new ECCurve.Fp(q, BigInteger.ZERO, BigInteger.valueOf(3));
        System.out.println(bnCurve.configure().create());
        ECPoint point = bnCurve.createPoint(BigInteger.ONE, BigInteger.valueOf(2));
        System.out.println(point.isValid());
        System.out.println(bnCurve.getInfinity());
        ECPoint raised = point.multiply(BigInteger.valueOf(123456789));
        System.out.println(raised.normalize());

        System.out.println(Arrays.toString(point.getEncoded(true)));
        final Keccak.DigestKeccak sha3 = new Keccak.Digest256();
        byte[] output = sha3.digest(DatatypeConverter.parseHexBinary("7b1cffef36bc044d4d86b29ca4bdd91e42c6e8193372ca09a109da9b44281e32"));
        System.out.println(DatatypeConverter.printHexBinary(output));
    }

    @Test
    public void testHashingOnCurve() {
        Curve25519 curve = new Curve25519();
        Curve25519FieldElement x = new Curve25519FieldElement(BigInteger.ZERO);
        ECFieldElement rhs = x.square().multiply(x.add(curve.getA())).add(curve.getB());
        System.out.println(curve.getA());
        System.out.println(curve.getB());
        ECFieldElement y = rhs.sqrt();
        System.out.println(y);
        if (y != null) {
            curve.validatePoint(x.toBigInteger(), y.toBigInteger());
        } else {
            throw new IllegalArgumentException("Y");
        }
    }

    @Test
    public void testSquareRoot() {
        BigInteger P = new BigInteger("21888242871839275222246405745257275088696311157297823662689037894645226208583");
        System.out.println(P.mod(BigInteger.valueOf(4)));
        System.out.println(P.isProbablePrime(50));
        BigInteger x = new BigInteger(256, new Random());
        BigInteger sqrt = x.modPow((P.add(BigInteger.ONE)).divide(BigInteger.valueOf(4)), P);
        System.out.println(x.modPow(P.min(BigInteger.ONE).shiftRight(1), P));
        System.out.println(sqrt);
        System.out.println(sqrt.modPow(BigInteger.TWO, P));
        System.out.println(x);
        System.out.println("Min x");
        BigInteger minX = P.min(x);
        BigInteger sqrtMin = minX.modPow(P.add(BigInteger.ONE).shiftRight(2), P);
        System.out.println(sqrtMin.modPow(BigInteger.TWO, P));
        System.out.println(minX);

    }

    @Test
    public void testBaretoNaehrig() {
        BigInteger P = new BigInteger("21888242871839275222246405745257275088696311157297823662689037894645226208583");
        BigInteger low = new BigInteger(
                "1101000000000000000010000000000000000000000010000000000000011",
                2);
        BigInteger high=ECBNCurve.calcU(256);

       BigInteger x=BigInteger.valueOf(4965661367192848881L);
        System.out.println(P);
        System.out.println(ECBNCurve.calcQ(x));
        BigInteger t=  BigInteger.valueOf(6).multiply(x).multiply(x).add(BigInteger.ONE); // 6*u^2 + 1
        System.out.println(t);
       BigInteger n = ECBNCurve.calcQ(x).add(BigInteger.ONE).subtract(t);
        System.out.println(n);
        BigInteger R = new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617");
        System.out.println(R);



    }
}
