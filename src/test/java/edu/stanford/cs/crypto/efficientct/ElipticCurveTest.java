package edu.stanford.cs.crypto.efficientct;

import edu.stanford.cs.crypto.efficientct.util.ECConstants;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

public class ElipticCurveTest {
    @Test
    public void verifyCurvePoint() {
        ECPoint g = ECConstants.G;
        ECConstants.BITCOIN_CURVE.validatePoint(g.getXCoord().toBigInteger(), g.getYCoord().toBigInteger());

        Assert.assertTrue("G not valid", g.isValid());
        Assert.assertTrue("G not valid", g.multiply(BigInteger.valueOf(1231513252113214L)).isValid());


    }

    @Test
    public void addition() {
        ECPoint g = ECConstants.G;
        ECPoint ten = g.multiply(BigInteger.TEN);
        Assert.assertEquals(ten, ten.normalize());
        BigInteger rand = new BigInteger(256, new SecureRandom());
        ECPoint large=g.multiply(rand);
        Assert.assertTrue("add not valid", large.add(ten).isValid());
        Assert.assertEquals(large.add(ten),g.multiply(rand.add(BigInteger.valueOf(10))));
        Assert.assertEquals(large.timesPow2(1),g.multiply(rand.add(rand)));
        Assert.assertNotEquals(large.timesPow2(1),g.multiply(rand.add(rand).add(BigInteger.ONE)));

        Assert.assertTrue("G not valid", g.isValid());
        Assert.assertTrue("G not valid", g.multiply(BigInteger.valueOf(1231513252113214L)).isValid());


    }
}
