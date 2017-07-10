package edu.stanford.cs.crypto.efficientct;/*
 * Decompiled with CFR 0_110.
 */

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP256K1FieldElement;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class ProofUtils {
    private static final ThreadLocal<MessageDigest> SHA256;
    private static final SecureRandom RNG;

    public static BigInteger computeChallenge(ECPoint... points) {
        MessageDigest sha = SHA256.get();
        for (ECPoint point : points) {
            sha.update(point.getEncoded(false));
        }
        byte[] hash = sha.digest();
        return new BigInteger(hash).mod(ECConstants.P);
    }
    public static BigInteger computeChallenge(Iterable<ECPoint> points) {
        MessageDigest sha = SHA256.get();
        for (ECPoint point : points) {
            sha.update(point.getEncoded(false));
        }
        byte[] hash = sha.digest();
        return new BigInteger(hash).mod(ECConstants.P);
    }

    public static BigInteger computeChallenge(BigInteger[] ints, ECPoint... points) {
        MessageDigest sha = SHA256.get();
        for(BigInteger integer:ints){
            sha.update(integer.toByteArray());
        }
        for (ECPoint point : points) {
            sha.update(point.getEncoded(false));
        }
        byte[] hash = sha.digest();
        return new BigInteger(hash).mod(ECConstants.P);
    }

    public static BigInteger challengeFromInts(BigInteger... integers) {
        MessageDigest sha = SHA256.get();
        for (BigInteger integer : integers) {
            sha.update(integer.toByteArray());
        }
        byte[] hash = sha.digest();
        return new BigInteger(hash).mod(ECConstants.P);
    }

    public static BigInteger hash(String string) {
        SHA256.get().update(string.getBytes());
        return new BigInteger(SHA256.get().digest());
    }

    public static BigInteger hash(String id, BigInteger salt) {
        SHA256.get().update(id.getBytes());
        SHA256.get().update(salt.toByteArray());
        return new BigInteger(SHA256.get().digest());
    }

    public static BigInteger randomNumber(int bits) {
        return new BigInteger(bits, RNG);
    }

    public static BigInteger randomNumber() {
        return ProofUtils.randomNumber(256);
    }

    public static ECPoint fromSeed(BigInteger seed) {
        SecP256K1Curve curve = new SecP256K1Curve();


        ECPoint point = null;
        boolean success = false;
        do {
            ECFieldElement x = new SecP256K1FieldElement(seed.mod(curve.getQ()));
            ECFieldElement rhs = x.square().multiply(x.add(curve.getA())).add(curve.getB());
            ECFieldElement y = rhs.sqrt();
            if (y != null) {
                point = curve.validatePoint(x.toBigInteger(), y.toBigInteger());

                success = true;
            } else {
                seed = seed.add(BigInteger.ONE);
            }
        } while (!success);
        return point;
    }

    static {
        RNG = new SecureRandom();
        SHA256 = ThreadLocal.withInitial(() -> {
                    try {
                        return MessageDigest.getInstance("SHA-256");
                    } catch (NoSuchAlgorithmException e) {
                        e.printStackTrace();
                        throw new IllegalStateException(e);
                    }
                }
        );
    }
}

