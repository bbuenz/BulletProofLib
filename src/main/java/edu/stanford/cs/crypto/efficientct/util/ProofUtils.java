package edu.stanford.cs.crypto.efficientct.util;/*
 * Decompiled with CFR 0_110.
 */

import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.djb.Curve25519FieldElement;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP256K1FieldElement;
import org.bouncycastle.math.ec.custom.sec.SecP256R1FieldElement;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class ProofUtils {
    private static final ThreadLocal<MessageDigest> KECCACK;
    private static final SecureRandom RNG;

    public static BigInteger computeChallenge(ECPoint... points) {
        MessageDigest sha = KECCACK.get();
        for (ECPoint point : points) {
            sha.update(point.getEncoded(false));
        }
        byte[] hash = sha.digest();
        return new BigInteger(hash).mod(ECConstants.P);
    }

    public static BigInteger computeChallenge(Iterable<ECPoint> points) {
        MessageDigest sha = KECCACK.get();
        for (ECPoint point : points) {
            sha.update(point.getEncoded(false));
        }
        byte[] hash = sha.digest();
        return new BigInteger(hash).mod(ECConstants.P);
    }

    public static BigInteger computeChallenge(BigInteger[] ints, ECPoint... points) {
        MessageDigest sha = KECCACK.get();
        for (BigInteger integer : ints) {
            sha.update(integer.toByteArray());
        }
        for (ECPoint point : points) {
            sha.update(point.getEncoded(false));
        }
        byte[] hash = sha.digest();
        return new BigInteger(hash).mod(ECConstants.P);
    }

    public static BigInteger challengeFromInts(BigInteger... integers) {
        MessageDigest sha = KECCACK.get();
        for (BigInteger integer : integers) {
            sha.update(integer.toByteArray());
        }
        byte[] hash = sha.digest();
        return new BigInteger(hash).mod(ECConstants.P);
    }

    public static BigInteger hash(String string) {
        KECCACK.get().update(string.getBytes());
        return new BigInteger(KECCACK.get().digest());
    }

    public static BigInteger hash(String id, BigInteger salt) {
        KECCACK.get().update(id.getBytes());
        KECCACK.get().update(salt.toByteArray());
        return new BigInteger(KECCACK.get().digest());
    }

    public static BigInteger randomNumber(int bits) {
        return new BigInteger(bits, RNG);
    }

    public static BigInteger randomNumber() {
        return ProofUtils.randomNumber(256);
    }

    public static ECPoint fromSeed(BigInteger seed) {
        ECCurve curve = ECConstants.BITCOIN_CURVE;


        ECPoint point = null;
        boolean success = false;
        do {
            ECFieldElement x = new SecP256K1FieldElement(seed.mod(ECConstants.P));

            ECFieldElement rhs = x.square().multiply(x.add(curve.getA())).add(curve.getB());

            //ECFieldElement rhs = x.squarePow(3).add(x.square().multiply(curve.getA())).add(x);
            ECFieldElement y = rhs.sqrt();
            if (y != null) {
                point = curve.validatePoint(x.toBigInteger(), y.toBigInteger());
            /*
            BigInteger p = ECConstants.P;
            BigInteger x = seed.mod(p);
            BigInteger rhs = x.pow(3).add(curve.getA().toBigInteger().multiply(x)).add(curve.getB().toBigInteger()).mod(p);
            BigInteger y = rhs.modPow(p.add(BigInteger.ONE).shiftRight(2), p);
            if (y.modPow(BigInteger.valueOf(2), p).equals(rhs)) {

                point = curve.validatePoint(x, y);
        */
                success = true;
            } else {
                seed = seed.add(BigInteger.ONE);
            }
        } while (!success);
        return point;
    }

    static {
        RNG = new SecureRandom();
        KECCACK = ThreadLocal.withInitial(Keccak.Digest256::new);
    }
}

