package edu.stanford.cs.crypto.efficientct.innerproduct;

import edu.stanford.cs.crypto.efficientct.Proof;
import edu.stanford.cs.crypto.efficientct.algebra.GroupElement;

import java.math.BigInteger;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Created by buenz on 6/28/17.
 */
public class InnerProductProof<T extends GroupElement<T>> implements Proof {
    private final List<T> L;
    private final List<T> R;
    private final BigInteger a;
    private final BigInteger b;

    public InnerProductProof(List<T> l, List<T> r, BigInteger a, BigInteger b) {
        this.L = l;
        this.R = r;
        this.a = a;
        this.b = b;
    }

    public List<T> getL() {
        return L;
    }

    public List<T> getR() {
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
        List<byte[]> byteArrs = Stream.concat(L.stream(), R.stream()).map(GroupElement::canonicalRepresentation).collect(Collectors.toList());
        byteArrs.add(a.toByteArray());
        byteArrs.add(b.toByteArray());
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
