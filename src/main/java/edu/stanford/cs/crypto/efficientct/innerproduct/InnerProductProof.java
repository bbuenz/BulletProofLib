package edu.stanford.cs.crypto.efficientct.innerproduct;

import edu.stanford.cs.crypto.efficientct.ECConstants;
import edu.stanford.cs.crypto.efficientct.Proof;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Created by buenz on 6/28/17.
 */
public class InnerProductProof implements Proof {
    private final List<ECPoint> L;
    private final List<ECPoint> R;
    private final BigInteger a;
    private final BigInteger b;

    public InnerProductProof(List<ECPoint> l, List<ECPoint> r, BigInteger a, BigInteger b) {
        L = l;
        R = r;
        this.a = a;
        this.b = b;
    }

    public List<ECPoint> getL() {
        return L;
    }

    public List<ECPoint> getR() {
        return R;
    }

    public BigInteger getA() {
        return a;
    }

    public BigInteger getB() {
        return b;
    }


    @Override
    public byte[] serialize() {
        List<byte[]> byteArrs = Stream.concat(L.stream(), R.stream()).map(p -> p.getEncoded(true)).collect(Collectors.toList());
        byteArrs.add(a.mod(ECConstants.P).toByteArray());
        byteArrs.add(b.mod(ECConstants.P).toByteArray());
        int totalBytes = byteArrs.stream().mapToInt(arr -> arr.length).sum();
        byte[] fullArray = new byte[totalBytes];
        int currIndex = 0;
        for (byte[] arr2 : byteArrs) {
            System.arraycopy(arr2, 0, fullArray, currIndex, arr2.length);
            currIndex += arr2.length;
        }
        return fullArray;
    }
}
