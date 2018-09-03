package edu.stanford.cs.crypto.efficientct.algebra;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public class BouncyCastleECPoint implements GroupElement<BouncyCastleECPoint> {
    public static int expCount = 0;
    public static int addCount = 0;
    protected final ECPoint point;

    BouncyCastleECPoint(ECPoint point) {
        this.point = point;
    }

    @Override
    public BouncyCastleECPoint add(BouncyCastleECPoint other) {
        ++addCount;
        return from(point.add(other.point));
    }

    @Override
    public BouncyCastleECPoint multiply(BigInteger exp) {
        ++expCount;
        return from(point.multiply(exp));
    }

    @Override
    public BouncyCastleECPoint negate() {
        return from(point.negate());
    }

    @Override
    public byte[] canonicalRepresentation() {

        return point.normalize().getEncoded(true);
    }

    @Override
    public String stringRepresentation() {
        return point.normalize().toString();
    }

    private static BouncyCastleECPoint from(ECPoint point) {
        return new BouncyCastleECPoint(point);
    }

    public ECPoint getPoint() {
        return point;
    }

    @Override
    public String toString() {
        ECPoint normalized = point.normalize();
        return String.format("0x%s, 0x%s", normalized.getXCoord(), normalized.getYCoord());
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
