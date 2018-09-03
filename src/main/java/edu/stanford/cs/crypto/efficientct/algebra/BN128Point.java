package edu.stanford.cs.crypto.efficientct.algebra;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Objects;

public class BN128Point implements GroupElement<BN128Point> {
    private final ECPoint point;

    BN128Point(ECPoint point) {
        this.point = point;
    }

    @Override
    public BN128Point add(BN128Point other) {
        return new BN128Point(point.add(other.point));
    }

    @Override
    public BN128Point multiply(BigInteger exp) {
        return new BN128Point(point.multiply(exp));
    }

    @Override
    public BN128Point negate() {
        return new BN128Point(point.negate());
    }

    @Override
    public byte[] canonicalRepresentation() {

        byte[] arr = new byte[64];
        if (point.isInfinity()) {
            return arr;
        }
        ECPoint normalizedPoint = point.normalize();
        BigInteger xCord = normalizedPoint.getXCoord().toBigInteger();
        int xLength = xCord.bitLength() / 8 + 1;
        System.arraycopy(xCord.toByteArray(), 0, arr, 32 - xLength, xLength);
        BigInteger yCord = normalizedPoint.getYCoord().toBigInteger();
        int yLength = yCord.bitLength() / 8 + 1;
        System.arraycopy(yCord.toByteArray(), 0, arr, 64 - yLength, yLength);
        return arr;
    }

    @Override
    public String stringRepresentation() {
        return point.normalize().toString();
    }

    @Override
    public String toString() {
        ECPoint normalized = point.normalize();
        return String.format("0x%s, 0x%s", normalized.getXCoord(), normalized.getYCoord());
    }

    public ECPoint getPoint() {
        return point;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        BN128Point that = (BN128Point) o;
        return Objects.equals(point, that.point);
    }

    @Override
    public int hashCode() {

        return Objects.hash(point);
    }
}
