package edu.stanford.cs.crypto.efficientct.circuit.groups;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public class BouncyCastleECPoint implements GroupElement<BouncyCastleECPoint> {
    private final ECPoint point;

    public BouncyCastleECPoint(ECPoint point) {
        this.point = point;
    }

    @Override
    public BouncyCastleECPoint add(BouncyCastleECPoint other) {
        return from(point.add(other.point));
    }

    @Override
    public BouncyCastleECPoint multiply(BigInteger exp) {
        return from(point.multiply(exp));
    }

    @Override
    public BouncyCastleECPoint negate() {
        return from(point.negate());
    }

    @Override
    public byte[] canonicalRepresentation() {
        return point.getEncoded(true);
    }

    @Override
    public String stringRepresentation() {
        return point.normalize().toString();
    }

    private static  BouncyCastleECPoint from(ECPoint point) {
        return new BouncyCastleECPoint(point);
    }

    public ECPoint getPoint() {
        return point;
    }

    @Override
    public String toString() {
        return point.normalize().toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        BouncyCastleECPoint that = (BouncyCastleECPoint) o;

        return point != null ? point.equals(that.point) : that.point == null;
    }

    @Override
    public int hashCode() {
        return point != null ? point.hashCode() : 0;
    }
}
