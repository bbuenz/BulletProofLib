package edu.stanford.cs.crypto.efficientct;

import edu.stanford.cs.crypto.efficientct.algebra.*;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

public class ElipticCurveTest {
    @Test
    public void verifyCurvePoint() {

        BN128Group group = new BN128Group();
        ECPoint g = group.generator().getPoint();
        group.getCurve().validatePoint(g.getXCoord().toBigInteger(), g.getYCoord().toBigInteger());

        Assert.assertTrue("G not valid", g.isValid());
        Assert.assertTrue("G not valid", g.multiply(BigInteger.valueOf(1231513252113214L)).isValid());


    }

    @Test
    public void addition() {
        ECPoint g = new Secp256k1().generator().getPoint();
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
        BN128Group bn128Group = new BN128Group();
        BN128Point point = bn128Group.mapInto(ProofUtils.hash("1"));
        System.out.println(point);
        for (int i = 0; i < 100; ++i) {
            System.out.println(bn128Group.mapInto(new BigInteger(256, new Random())));
        }
    }

    @Test
    public void testSubGroup() {
        BN128Group bn128Group = new BN128Group();
        BN128Point point = bn128Group.mapInto(ProofUtils.hash("1"));
        System.out.println(point);
        for (int i = 0; i < 100; ++i) {
            BN128Point x = bn128Group.mapInto(new BigInteger(256, new Random()));
            Assert.assertEquals(x.multiply(bn128Group.groupOrder()), bn128Group.zero());
        }
    }

    @Test
    public void testInversion() {
        BN128Group bn128Group = new BN128Group();
        BN128Point point = bn128Group.mapInto(ProofUtils.hash("1"));
        System.out.println(point.multiply(BigInteger.valueOf(-1)).add(point));


    }
}
