package edu.stanford.cs.crypto.efficientct.algebra;


/**
 * ECBNCurve.java
 * <p>
 * Set-up for Barreto-Naehrig (BN) pairing-friendly elliptic curves.
 * <p>
 * Adapted from file BNParams.java with
 * Copyright (C) Paulo S. L. M. Barreto.
 * <p>
 * <p>
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * <p>
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * <p>
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

/**
 * Class for an elliptic curve over F_p^2
 */
public class ECBNCurve extends ECCurve.Fp {


    public static boolean curveContains(ECCurve curve, ECFieldElement x,
                                        ECFieldElement y) {
        ECFieldElement LHS = y.multiply(y);
        ECFieldElement RHS = x.multiply(x).multiply(x).add(
                curve.getA().multiply(x)).add(curve.getB());
        return LHS.equals(RHS);
    }

    /**
     * Convenient BigInteger constants
     */

    static final BigInteger _0 = BigInteger.valueOf(0L), _1 = BigInteger
            .valueOf(1L), _2 = BigInteger.valueOf(2L), _3 = BigInteger
            .valueOf(3L), _4 = BigInteger.valueOf(4L), _5 = BigInteger
            .valueOf(5L), _6 = BigInteger.valueOf(6L), _7 = BigInteger
            .valueOf(7L), _9 = BigInteger.valueOf(9L), _24 = BigInteger
            .valueOf(24L);

    /**
     * Rabin-Miller certainty used for primality testing
     */

    static final int PRIMALITY_CERTAINTY = 20;

    /**
     * Prime of the underlying finite field F_q
     */
    BigInteger q;

    /**
     * BN index -- the curve BN(u) is defined by the following parameters:
     * <p>
     * t = 6*u^2 + 1 p = 36*u^4 + 36*u^3 + 24*u^2 + 6*u + 1 n = 36*u^4 + 36*u^3
     * + 18*u^2 + 6*u + 1
     * <p>
     * BN(u)/GF(p): y^2 = x^3 + b, #BN(u)(GF(p)) = n, n = p + 1 - t.
     * <p>
     * Restrictions: p = 3 (mod 4) and p = 4 (mod 9).
     */

    private BigInteger u;

    /**
     * Trace of the Frobenius endomorphism
     */

    private BigInteger t;

    /**
     * Primitive cube root of unity mod p
     */

    private BigInteger zeta;

    /**
     * Prime curve order
     */

    private BigInteger n;

    /**
     * Compute BN parameters for a given field size, which must be a multiple of
     * 8 between 56 and 512 (inclusive).
     * <p>
     * The BN parameter u is the largest one with the smallest possible Hamming
     * weight, leading to a field prime p satisfying both p = 3 (mod 4) and p =
     * 4 (mod 9), speeding up the computation of square and cube roots in both
     * F_p and F_{p^2}. Besides, for i \in F_{p^2} such that i^2 + 1 = 0, the
     * element v = 1 + i is neither a square nor a cube, so that one can
     * represent F_{p^2m} as F_{p^2}[z]/(z^m - 1/v) or F_{p^2}[z]/(z^m - v) for
     * m = 2, 3, 6.
     * <p>
     * The standard curve is E(F_p): y^2 = x^3 + 3, whose default generator is G
     * = (1, 2). Its (sextic) twist is E'(F_{p^2}): y'^2 = x'^3 + 3v, whose
     * default generator has the form G' = [p-1+t]*(1, y') for some y'.
     * <p>
     * The standard isomorphism psi: E'(F_{p^2}) -> E(F_{p^12}) is defined as
     * psi(x', y') = (x'*z^2, y'*z^3) for the first representation of F_{p^12}
     * above, and as psi(x', y') = (x'/z^2, y'/z^3) = (x'*z^4/v, y'*z^3/v) for
     * the second representation.
     */


    public ECBNCurve(BigInteger fieldBits) {
        super(calcQ(fieldBits), _0, _3);
        u = fieldBits;
        // p = 36*u^4 + 36*u^3 + 24*u^2 + 6*u + 1 = (((u + 1)*6*u + 4)*u +
        // 1)*6*u + 1
        assert (q.mod(_4).intValue() == 3 || q.mod(_9).intValue() == 4);
        assert (q.isProbablePrime(PRIMALITY_CERTAINTY));
        t = _6.multiply(u).multiply(u).add(_1); // 6*u^2 + 1
        // ht = q.subtract(_1).add(t);
        // n = 36*u^4 + 36*u^3 + 18*u^2 + 6*u + 1
        n = q.add(_1).subtract(t);
        assert (n.isProbablePrime(PRIMALITY_CERTAINTY));
        // zeta = 18*u^3 + 18*u^2 + 9*u + 1;
        zeta = _9.multiply(u).multiply(
                u.shiftLeft(1).multiply(u.add(_1)).add(_1)).add(_1);
        System.out.println("BNCurve y^2 = x^3 + 3 created with index u = " + u
                + ", prime q = " + q + ", trace t = " + t
                + ", curve order n = " + n + " (" + n.bitLength() + " bits).");
    }


    public static BigInteger calcQ(BigInteger u) {
        return u.add(_1).multiply(_6.multiply(u)).add(_4).multiply(u).add(_1)
                .multiply(_6.multiply(u)).add(_1);
    }


    public static BigInteger calcU(int fieldBits) {
        BigInteger u = null;
        switch (fieldBits) {
            case 27:
                u = BigInteger.valueOf(-41L); // debugging only
                break;
            case 56:
                u = new BigInteger("1011001111011", 2); // Hamming weight 9
                break;
            case 64:
                u = new BigInteger("110010000111111", 2); // Hamming weight 9
                break;
            case 72:
                u = new BigInteger("10110000111001011", 2); // Hamming weight 9
                break;
            case 80:
                u = new BigInteger("1101000010001011011", 2); // Hamming weight
                // 9
                break;
            case 88:
                u = new BigInteger("110000010010001001111", 2); // Hamming
                // weight 9
                break;
            case 96:
                u = new BigInteger("11010000000000000010111", 2); // Hamming
                // weight 7
                break;
            case 104:
                u = new BigInteger("1101000000000000000100011", 2); // Hamming
                // weight 6
                break;
            case 112:
                u = new BigInteger("101100100000000100000000011", 2); // Hamming
                // weight
                // 7
                break;
            case 120:
                u = new BigInteger("11000000100000000100100000011", 2); // Hamming
                // weight
                // 7
                break;
            case 128:
                u = new BigInteger("1100100000100000000000001000111", 2); // Hamming
                // weight
                // 8
                break;
            case 136:
                u = new BigInteger("110001000000000100000100000000111", 2); // Hamming
                // weight
                // 8
                break;
            case 144:
                u = new BigInteger("11000100000000000000100000100000011", 2); // Hamming
                // weight
                // 7
                break;
            case 152:
                u = new BigInteger("1100100000000000000000100000000100011", 2); // Hamming
                // weight
                // 7
                break;
            case 160:
                u = new BigInteger("110100001000000000000100010000000000011", 2); // ***
                // ISO,
                // Hamming
                // weight
                // 8
                break;
            case 168:
                u = new BigInteger("11000010010000100000000000000000000000011",
                        2); // Hamming weight 7
                break;
            case 176:
                u = new BigInteger(
                        "1100000000000000000000100000000000001001011", 2); // Hamming
                // weight
                // 7
                break;
            case 184:
                u = new BigInteger(
                        "110000000000100000000000001000000001000000011", 2); // Hamming
                // weight
                // 7
                break;
            case 192:
                u = new BigInteger(
                        "11000000000000000001000000000000000010000010011", 2); // ***
                // ISO,
                // Hamming
                // weight
                // 7
                break;
            case 200:
                u = new BigInteger(
                        "1101000100000100000000000000000000100000000000011", 2); // Hamming
                // weight
                // 8
                break;
            case 208:
                u = new BigInteger(
                        "110000000000000000000000000000000000000000100000011",
                        2); // Hamming weight 5
                break;
            case 216:
                u = new BigInteger(
                        "11000000001000000000000010000000000100000000000000011",
                        2); // Hamming weight 7
                break;
            case 224:
                u = new BigInteger(
                        "1100000000000000000000100000001000000000000001000000011",
                        2); // *** ISO, Hamming weight 7
                break;
            case 232:
                u = new BigInteger(
                        "110000100000000000001000000000000001000000000000000000011",
                        2); // Hamming weight 7
                break;
            case 240:
                u = new BigInteger(
                        "11010000000000000010000000000000000000000000000000000000111",
                        2); // Hamming weight 7
                break;
            case 248:
                u = new BigInteger(
                        "1101000000000000000010000000000000000000000010000000000000011",
                        2); // Hamming weight 7
                break;
            case 256:
                u = new BigInteger(
                        "110000010000000000000000000000000000000000001000000000001000011",
                        2); // *** ISO, Hamming weight 7
                break;
            case 264:
                u = new BigInteger(
                        "11000000000000000001000000000000000000000000000000000100000000011",
                        2); // Hamming weight 6
                break;
            case 272:
                u = new BigInteger(
                        "1100000100000000000010000000000000000000000000000000000000001000011",
                        2); // Hamming weight 7
                break;
            case 280:
                u = new BigInteger(
                        "110000000000001000000000000000000000000000000000000000000000011000011",
                        2); // Hamming weight 7
                break;
            case 288:
                u = new BigInteger(
                        "11000000000000000000000000000000000100000001000000000000000000000000011",
                        2); // Hamming weight 6
                break;
            case 296:
                u = new BigInteger(
                        "1100000000000000000000100000000000000000100000000000000000000000000100011",
                        2); // Hamming weight 7
                break;
            case 304:
                u = new BigInteger(
                        "110000000000000100000000000000000000000000000000000000000001000000000000011",
                        2); // Hamming weight 6
                break;
            case 312:
                u = new BigInteger(
                        "11000000100000000000000000000010000000000000000000000000000000010000000000011",
                        2); // Hamming weight 7
                break;
            case 320:
                u = new BigInteger(
                        "1100000000000000000000000000000000000100100000000000000000100000000000000000011",
                        2); // Hamming weight 7
                break;
            case 328:
                u = new BigInteger(
                        "110000000000000000000000000000000000000000100001000000000000000000000000001000011",
                        2); // Hamming weight 7
                break;
            case 336:
                u = new BigInteger(
                        "11000100100000000000000000000000000000000000000000000000000000100000000000000000011",
                        2); // Hamming weight 7
                break;
            case 344:
                u = new BigInteger(
                        "1100000010000000000000000000000000000000000000000000000000001000000000000100000000011",
                        2); // Hamming weight 7
                break;
            case 352:
                u = new BigInteger(
                        "110000000000000001000000000000000000000000000000000000000000000000000000001000000000111",
                        2); // Hamming weight 7
                break;
            case 360:
                u = new BigInteger(
                        "11010000000100000001000000000000000000000000000000000000000000000010000000000000000000011",
                        2); // Hamming weight 8
                break;
            case 368:
                u = new BigInteger(
                        "1100100000000000000000000000000000000000001001000000000000000000000000000000000000000000011",
                        2); // Hamming weight 7
                break;
            case 376:
                u = new BigInteger(
                        "110001001000000000000000000000000000000000000000000000000000000000000000000000000000000000111",
                        2); // Hamming weight 7
                break;
            case 384:
                u = new BigInteger(
                        "11001000000000000010000000000000000000000000000000000000000000000100000000000000000000000000011",
                        2); // *** ISO, Hamming weight 7
                break;
            case 392:
                u = new BigInteger(
                        "1100001000000001000000000000000000000000000000000000000000000000000000000000000000100000000000011",
                        2); // Hamming weight 7
                break;
            case 400:
                u = new BigInteger(
                        "110000000000000000000000000000000000000000000000000000000000000000000000000000000100000001000000011",
                        2); // Hamming weight 6
                break;
            case 408:
                u = new BigInteger(
                        "11000010000000000000000000000000110000000000000000000000000000000000000000000000000000000000000000011",
                        2); // Hamming weight 7
                break;
            case 416:
                u = new BigInteger(
                        "1100000000100000000000100000000000000000000000000000000100000000000000000000000000000000000000000000011",
                        2); // Hamming weight 7
                break;
            case 424:
                u = new BigInteger(
                        "110001000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000100000011",
                        2); // Hamming weight 7
                break;
            case 432:
                u = new BigInteger(
                        "11000100000000000000000000000000000000000000000000000000100000100000000000000000000000000000000000000000011",
                        2); // Hamming weight 7
                break;
            case 440:
                u = new BigInteger(
                        "1100000000000000000000000000000100000000000000000000000000000000000000000000100000100000000000000000000000011",
                        2); // Hamming weight 7
                break;
            case 448:
                u = new BigInteger(
                        "110000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000001000000000000011",
                        2); // Hamming weight 6
                break;
            case 456:
                u = new BigInteger(
                        "11001000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000100000000000000011",
                        2); // Hamming weight 7
                break;
            case 464:
                u = new BigInteger(
                        "1100000000000000000000000000000000000000000000000000000100000000001000000000000000000010000000000000000000000000011",
                        2); // Hamming weight 7
                break;
            case 472:
                u = new BigInteger(
                        "110000000000100000100100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000011",
                        2); // Hamming weight 7
                break;
            case 480:
                u = new BigInteger(
                        "11000000000000000000000100000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000011",
                        2); // Hamming weight 6
                break;
            case 488:
                u = new BigInteger(
                        "1100000001000000000000000000000000000000001000000000000000000000000000000000100000000000000000000000000000000000000000011",
                        2); // Hamming weight 7
                break;
            case 496:
                u = new BigInteger(
                        "110000100000000000000000000000000000000000000000000000000000000001000000000000000000001000000000000000000000000000000000011",
                        2); // Hamming weight 7
                break;
            case 504:
                u = new BigInteger(
                        "11000000000000000010000000000000010000000000000000000000000000000000000000100000000000000000000000000000000000000000000000011",
                        2); // Hamming weight 7
                break;
            case 512:
                u = new BigInteger(
                        "1100001000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000001000000000000000011",
                        2); // *** ISO, Hamming weight 7
                break;
            default:
                throw new IllegalArgumentException(
                        "Field size in bits must be a multiple of 8 between 56 and 512");
        }
        return u;
    }


    public BigInteger getQ() {
        return q;
    }


    public BigInteger getIndex() {
        return u;
    }


    public BigInteger getTrace() {
        return t;
    }


    public BigInteger getZeta() {
        return zeta;
    }


    public BigInteger getOrder() {
        return n;
    }


    public int getFieldSize() {
        return q.bitLength();
    }


    public ECFieldElement fromBigInteger(BigInteger x) {
        return new ECFieldElement.Fp(this.q, x);
    }


    public ECPoint createPoint(BigInteger x, BigInteger y,
                               boolean withCompression) {
        return null;
    }


    public ECPoint decodePoint(byte[] encoded) {
        return null;
    }


    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (!(o instanceof ECBNCurve)) {
            return false;
        }
        ECBNCurve other = (ECBNCurve) o;
        return q.equals(other.getQ()) && u.equals(other.getIndex());
    }

}
