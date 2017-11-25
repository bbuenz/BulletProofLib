package edu.stanford.cs.crypto.efficientct.util;/*
 * Decompiled with CFR 0_110.
 */

import edu.stanford.cs.crypto.efficientct.circuit.groups.GroupElement;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256K1FieldElement;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;

public class ProofUtils {
    private static final ThreadLocal<MessageDigest> KECCACK;
    private static final SecureRandom RNG;

    public static <T extends GroupElement<T>> BigInteger computeChallenge(BigInteger q,T... points) {
        MessageDigest sha = KECCACK.get();
        for (T point : points) {
            sha.update(point.canonicalRepresentation());
        }
        byte[] hash = sha.digest();
        return new BigInteger(hash).mod(q);
    }

    public static <T extends GroupElement<T>> BigInteger computeChallenge(BigInteger q,Iterable<T> points) {
        MessageDigest sha = KECCACK.get();
        for (T point : points) {
            sha.update(point.canonicalRepresentation());
        }
        byte[] hash = sha.digest();
        return new BigInteger(hash).mod(q);
    }

    public static <T extends GroupElement<T>> BigInteger computeChallenge(BigInteger q,BigInteger[] ints, T... points) {
        MessageDigest sha = KECCACK.get();
        for (BigInteger integer : ints) {
            sha.update(integer.toByteArray());
        }
        for (T point : points) {
            sha.update(point.canonicalRepresentation());
        }
        byte[] hash = sha.digest();
        return new BigInteger(hash).mod(q);
    }

    public static BigInteger challengeFromints(BigInteger q, BigInteger... ints){
        MessageDigest sha = KECCACK.get();
        for (BigInteger integer : ints) {
            sha.update(integer.toByteArray());
        }
        byte[] hash = sha.digest();
        return new BigInteger(hash).mod(q);
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


    static {
        RNG = new SecureRandom();
        KECCACK = ThreadLocal.withInitial(Keccak.Digest256::new);
    }
}

