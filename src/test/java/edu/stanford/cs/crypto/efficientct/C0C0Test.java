package edu.stanford.cs.crypto.efficientct;

import edu.stanford.cs.crypto.efficientct.algebra.BouncyCastleCurve;
import edu.stanford.cs.crypto.efficientct.algebra.BouncyCastleECPoint;
import edu.stanford.cs.crypto.efficientct.algebra.C0C0Group;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;
import org.bouncycastle.math.ec.*;
import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

public class C0C0Test {
    @Test
    public void verifyCurvePoint() {

        BouncyCastleCurve group = new C0C0Group();
        ECPoint g = group.generator().getPoint();
        group.getCurve().validatePoint(g.getXCoord().toBigInteger(), g.getYCoord().toBigInteger());

        Assert.assertTrue("G not valid", g.isValid());
        Assert.assertTrue("G not valid", g.multiply(BigInteger.valueOf(1231513252113214L)).isValid());


    }

    @Test
    public void addition() {
        ECPoint g = new C0C0Group().generator().getPoint();
        ECPoint ten = g.multiply(BigInteger.TEN);
        Assert.assertEquals(ten, ten.normalize());
        BigInteger rand = new BigInteger(256, new SecureRandom());
        ECPoint large = g.multiply(rand);
        Assert.assertTrue("add not valid", large.add(ten).isValid());
        Assert.assertEquals(large.add(ten), g.multiply(rand.add(BigInteger.valueOf(10))));
        Assert.assertEquals(large.timesPow2(1), g.multiply(rand.add(rand)));
        Assert.assertNotEquals(large.timesPow2(1), g.multiply(rand.add(rand).add(BigInteger.ONE)));

        Assert.assertTrue("G not valid", g.isValid());
        Assert.assertTrue("G not valid", g.multiply(BigInteger.valueOf(1231513252113214L)).isValid());


    }

    @Test
    public void testHashing() {
        C0C0Group c0c0Group = new C0C0Group();
        BouncyCastleECPoint point = c0c0Group.mapInto(ProofUtils.hash("1"));
        System.out.println(point);
        for (int i = 0; i < 100; ++i) {
            BouncyCastleECPoint x = c0c0Group.mapInto(new BigInteger(256, new Random()));
            Assert.assertTrue(x.getPoint().isValid());
            x.multiply(BigInteger.valueOf(10));
            x.multiply(new BigInteger(300, new Random()));

            System.out.println(x);
        }
    }

    @Test
    public void testSubGroup() {
        C0C0Group c0c0Group = new C0C0Group();
        BouncyCastleECPoint point = c0c0Group.mapInto(ProofUtils.hash("1"));
        System.out.println(point);
        for (int i = 0; i < 100; ++i) {
            System.out.println(i);
            BouncyCastleECPoint x = c0c0Group.mapInto(new BigInteger(100, new Random()));
            Assert.assertTrue(x.getPoint().isValid());
            BouncyCastleECPoint raise = x.multiply(c0c0Group.groupOrder());
            Assert.assertTrue(raise.getPoint().isValid());

            Assert.assertEquals(raise, c0c0Group.zero());
        }
    }


    @Test
    public void testInversion() {
        C0C0Group bn128Group = new C0C0Group();
        BouncyCastleECPoint point = bn128Group.mapInto(ProofUtils.hash("1"));
        System.out.println(point.multiply(BigInteger.valueOf(-1)).add(point));


    }

    @Test
    public void testMontgomery() {
        C0C0Group bn128Group = new C0C0Group();
        BouncyCastleECPoint point = bn128Group.generator().multiply(BigInteger.TEN);
        System.out.println(bn128Group.toMontgomery(bn128Group.generator()));
        System.out.println(bn128Group.toMontgomery(point));
    }
    @Test
    public void testMultiExpMontgomery() {
        C0C0Group bn128Group = new C0C0Group();
        BouncyCastleECPoint g = bn128Group.mapInto(ProofUtils.hash("g"));
        BouncyCastleECPoint h = bn128Group.mapInto(ProofUtils.hash("h"));
        BigInteger exp1=new BigInteger(256, new Random(13));
        BigInteger exp2=new BigInteger(256, new Random(14));
        System.out.printf("exp1=%s\n",exp1);
        System.out.printf("exp2=%s\n",exp2);
        System.out.printf("g=EMont(%s)\n",bn128Group.toMontgomery(g));
        System.out.printf("h=EMont(%s)\n",bn128Group.toMontgomery(h));
        System.out.printf("exp1*g+exp2*h==EMont([%s])\n",bn128Group.toMontgomery(g.multiply(exp1).add(h.multiply(exp2))));
    }


    @Test
    public void additionMult() {
        C0C0Group c0C0Group = new C0C0Group();
        BouncyCastleECPoint g = c0C0Group.mapInto(ProofUtils.hash("1234"));
        BouncyCastleECPoint g1000 = g.multiply(BigInteger.valueOf(1000));
        BouncyCastleECPoint temp = c0C0Group.zero();
        for (int i = 0; i < 1000; ++i) {
            temp = temp.add(g);
        }
        System.out.println(g1000.equals(temp));


    }

    @Test
    public void testMul() {
        C0C0Group c0C0Group = new C0C0Group();
        BouncyCastleECPoint g = c0C0Group.mapInto(ProofUtils.hash("1234"));
        BigInteger exp = new BigInteger(300, new Random());
        BouncyCastleECPoint result1 = g.multiply(exp);

        BouncyCastleECPoint result2 = g.multiply(exp.mod(c0C0Group.groupOrder()));
        Assert.assertEquals(result1, result2);
        BouncyCastleECPoint result3 = g.multiply(c0C0Group.groupOrder());
        Assert.assertEquals(result3, c0C0Group.zero());

    }

    @Test
    public void testMultiplier() {
        C0C0Group c0C0Group = new C0C0Group();
        ECMultiplier montgomeryLadder = new DoubleAddMultiplier();
        ECCurve curve = c0C0Group.getCurve().configure().setMultiplier(montgomeryLadder).create();

        BigInteger seed = BigInteger.valueOf(3);
        System.out.println(seed);
        BouncyCastleECPoint x = c0C0Group.mapInto(seed);
        System.out.println(x);
        System.out.println(x.getPoint().isValid());
        ECPoint result = montgomeryLadder.multiply(x.getPoint(), c0C0Group.groupOrder());
        System.out.println(result);
        System.out.println(result.isValid());
        System.out.println(result.isInfinity());

    }
}
