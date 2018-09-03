package edu.stanford.cs.crypto.efficientct.zetherprover;

import edu.stanford.cs.crypto.efficientct.Proof;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class SigmaProof implements Proof {
    private final BigInteger c;
    private final BigInteger sX;
    private final BigInteger sR;

    public SigmaProof(BigInteger c, BigInteger sX, BigInteger sR) {
        this.c = c;
        this.sX = sX;
        this.sR = sR;
    }

    public BigInteger getsX() {
        return sX;
    }

    public BigInteger getsR() {
        return sR;
    }


    public BigInteger getC() {
        return c;
    }


    @Override
    public byte[] serialize() {
        List<byte[]> arrs = Arrays.asList(c.toByteArray(), sX.toByteArray(), sR.toByteArray());
        int sum = arrs.stream().mapToInt(arr -> arr.length).sum();
        byte[] arr = new byte[sum];
        int currIndex = 0;
        for (byte[] arr2 : arrs) {
            System.arraycopy(arr2, 0, arr, currIndex, arr2.length);
            currIndex += arr2.length;
        }
        return arr;
    }

    public String toStringArray() {
        BigInteger[] arr = new BigInteger[]{sX, sR, c};
        return Arrays.stream(arr).map(bi -> bi.toString(16)).map("0x"::concat).collect(Collectors.joining(", "));
    }

    @Override
    public String toString() {
        return "SigmaProof{" +
                "c=" + c +
                ", sX=" + sX +
                ", sR=" + sR +
                '}';
    }
}
