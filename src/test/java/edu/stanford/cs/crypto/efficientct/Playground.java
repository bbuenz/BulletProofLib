package edu.stanford.cs.crypto.efficientct;

import cyclops.collections.mutable.ListX;
import edu.stanford.cs.crypto.efficientct.algebra.*;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;
import edu.stanford.cs.crypto.efficientct.util.TonelliShanks;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.djb.Curve25519;
import org.bouncycastle.math.ec.custom.djb.Curve25519FieldElement;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;
import org.web3j.crypto.Hash;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.BitSet;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class Playground {
    @Test
    public void testPlayGround() {
        BigInteger a = new BigInteger("ee6efb5a4ec248b5a6ef16f9793864bb5e3efda61f72f959795777f7184adfbc", 16);
        BigInteger b = new BigInteger("9d10acf2556e4601da02910c082bf6cc65564327b32b40f7718af73fc096cd65", 16);
        ListX<BigInteger> bigIntList = ListX.of(a, b);
        ListX<BigInteger> other = bigIntList.map(bi -> bi.mod(BigInteger.TEN));
        System.out.println(bigIntList);
        System.out.println(other);
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
        System.out.println(sqrt.modPow(BigInteger.valueOf(2), P));
        System.out.println(x);
        System.out.println("Min x");
        BigInteger minX = P.min(x);
        BigInteger sqrtMin = minX.modPow(P.add(BigInteger.ONE).shiftRight(2), P);
        System.out.println(sqrtMin.modPow(BigInteger.valueOf(2), P));
        System.out.println(minX);

    }

    @Test
    public void testBaretoNaehrig() {
        BigInteger P = new BigInteger("21888242871839275222246405745257275088696311157297823662689037894645226208583");
        BigInteger low = new BigInteger(
                "1101000000000000000010000000000000000000000010000000000000011",
                2);
        BigInteger high = ECBNCurve.calcU(256);

        BigInteger x = BigInteger.valueOf(4965661367192848881L);
        System.out.println(P);
        System.out.println(ECBNCurve.calcQ(x));
        BigInteger t = BigInteger.valueOf(6).multiply(x).multiply(x).add(BigInteger.ONE); // 6*u^2 + 1
        System.out.println(t);
        BigInteger n = ECBNCurve.calcQ(x).add(BigInteger.ONE).subtract(t);
        System.out.println(n);
        BigInteger R = new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617");
        System.out.println(R);


    }

    @Test
    public void testShift() {
        BigInteger[] xs = new BigInteger[]{ProofUtils.hash("1"), ProofUtils.hash("2"), ProofUtils.hash("3"), ProofUtils.hash("4"), ProofUtils.hash("5")};
        BigInteger P = new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617");
        List<BigInteger> exponents = Stream.generate(() -> BigInteger.ONE).limit(32).collect(Collectors.toList());
        String arrString = Arrays.stream(xs).map(bi -> String.format("[\"0x%s\",\"0x%s\"]", bi.mod(P).toString(16), bi.modPow(BigInteger.valueOf(2), P).toString(16))).collect(Collectors.joining(","));

        System.out.println("[" + arrString + "]");
        int n = 32;
        for (int i = 0; i < n; ++i) {
            for (int j = 0; j < xs.length; ++j) {
                if ((i & (1 << j)) == 0) {
                    System.out.println(i + " " + j);

                    exponents.set(i, exponents.get(i).multiply(xs[xs.length - j - 1].modInverse(P)).mod(P));
                } else {
                    exponents.set(i, exponents.get(i).multiply(xs[xs.length - j - 1]).mod(P));

                }
            }
        }
        System.out.println(exponents);
        BitSet bitSet = new BitSet(32);
        bitSet.set(0);
        BigInteger[] otherExponents = new BigInteger[n];

        otherExponents[0] = Arrays.stream(xs).reduce(BigInteger.ONE, (l, r) -> l.multiply(r).mod(P)).modInverse(P);
        String[] exps = new String[32];
        for (int i = 0; i < 16; ++i) {
            for (int j = 0; (1 << j) + i < 32; ++j) {

                int i1 = i + (1 << j);
                if (bitSet.get(i1)) {

                } else {
                    exps[i1] = (String.format("exponents[%1$d]=EC.modmul(exponents[%2$d],xs[%3$d][1]);", i1, i, xs.length - j - 1));
                    otherExponents[i1] = otherExponents[i].multiply(xs[xs.length - j - 1].pow(2)).mod(P);
                    bitSet.set(i1);
                }
            }
        }
        Arrays.stream(exps).forEach(System.out::println);
        System.out.println(Arrays.toString(otherExponents));
    }

    @Test
    public void testBN128() {
        String message = "Hello World";
        BN128Group group = new BN128Group();
        BigInteger x = ProofUtils.randomNumber();
        BN128Point point = group.mapInto(ProofUtils.hash(message));
        System.out.println(point.multiply(x).stringRepresentation());

    }

    @Test
    public void testOrder() {
        BigInteger P = new BigInteger("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", 16);

        BigInteger PBIGINT = new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617");
        System.out.println(P);
        System.out.println(PBIGINT);
        TonelliShanks.Solution root = TonelliShanks.ts(new BigInteger("16213513238399463127589930181672055621146936592900766180517188286352452147890"), P);
        System.out.println(root.root1);
        System.out.println(root.root2);
        System.out.println(root.exists);
        BigInteger x = BigInteger.valueOf(4);
        BigInteger y = new BigInteger("5854969154019084038134685408453962516899849177257040453511959087213437462470");
        BigInteger a = new BigInteger("126932");
        BigInteger yPrime = x.modPow(BigInteger.valueOf(3), P).add(a.multiply(x.pow(2))).add(x).mod(P);
        System.out.println(y);
        System.out.println(yPrime);
        System.out.println(y.modPow(BigInteger.valueOf(2), P));
        BigInteger newX = x.add(a.multiply(BigInteger.valueOf(3).modInverse(P))).mod(P);
        System.out.println(newX);
        BigInteger newA = BigInteger.valueOf(3).subtract(a.pow(2)).multiply(BigInteger.valueOf(3).modInverse(P)).mod(P);
        System.out.println("NEW A: " + newA);
        BigInteger A = new BigInteger("10216f7ba065e00de81ac1e7808072c9b8114d6d7de87adb16a0a7300fe37d7c", 16);

        System.out.println(A);

        BigInteger newB = BigInteger.valueOf(2).multiply(a.pow(3)).subtract(a.multiply(BigInteger.valueOf(9))).multiply(BigInteger.valueOf(27).modInverse(P)).mod(P);
        System.out.println("NEW B: " + newB);
        BigInteger B = new BigInteger("395a6ff073315586c77b94fe3aac42cd3921134c6a570a276cee7d21e37550a", 16);
        System.out.println(B);
        System.out.println(newX.pow(3).add(newX.multiply(newA)).add(newB).mod(P));
        System.out.println(y.modPow(BigInteger.valueOf(2), P));
        System.out.println(newX);
        BigInteger ORDER = new BigInteger("2736030358979909402780800718157159386074658810754251464600343418943805806723");

        ECCurve curve = new ECCurve.Fp(P, newA, newB, ORDER, BigInteger.valueOf(8));
        System.out.println(newX.compareTo(P));
        ECPoint point = curve.createPoint(newX, y);
        System.out.println(P.mod(BigInteger.valueOf(8)));
        System.out.println(new C0C0Group().mapInto(BigInteger.valueOf(453535)));
        System.out.println(point.multiply(C0C0Group.ORDER).multiply(BigInteger.valueOf(8)));
        System.out.println(new BigInteger(1, Hex.decode("1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED")).isProbablePrime(40));
        System.out.println(ORDER.multiply(BigInteger.valueOf(8)));
        System.out.println("Order comparison " + P.compareTo(ORDER));
    }

}
