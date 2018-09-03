package edu.stanford.cs.crypto.efficientct.rangeproof;

import edu.stanford.cs.crypto.efficientct.Proof;
import edu.stanford.cs.crypto.efficientct.algebra.GroupElement;
import edu.stanford.cs.crypto.efficientct.innerproduct.InnerProductProof;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by buenz on 7/1/17.
 */
public class RangeProof<T extends GroupElement<T>> implements Proof {
    private final T aI;
    private final T s;
    private final GeneratorVector<T> tCommits;
    private final BigInteger tauX;
    private final BigInteger mu;
    private final BigInteger t;
    private final InnerProductProof<T> productProof;

    public RangeProof(T aI, T s, GeneratorVector<T> tCommits, BigInteger tauX, BigInteger mu, BigInteger t, InnerProductProof<T> productProof) {
        this.aI = aI;
        this.s = s;
        this.tCommits = tCommits;
        this.tauX = tauX;
        this.mu = mu;
        this.t = t;
        this.productProof = productProof;
    }

    public T getaI() {
        return aI;
    }

    public T getS() {
        return s;
    }


    public BigInteger getTauX() {
        return tauX;
    }

    public BigInteger getMu() {
        return mu;
    }

    public BigInteger getT() {
        return t;
    }

    public InnerProductProof<T> getProductProof() {
        return productProof;
    }

    public GeneratorVector<T> gettCommits() {
        return tCommits;
    }

    @Override
    public byte[] serialize() {
        List<byte[]> byteArrs = new ArrayList<>();
        byteArrs.add(productProof.serialize());
        byteArrs.add(aI.canonicalRepresentation());
        byteArrs.add(s.canonicalRepresentation());
        tCommits.stream().map(GroupElement::canonicalRepresentation).forEach(byteArrs::add);
        BigInteger q = tCommits.getGroup().groupOrder();
        byteArrs.add(tauX.mod(q).toByteArray());
        byteArrs.add(mu.mod(q).toByteArray());
        byteArrs.add(t.mod(q).toByteArray());

        int totalBytes = byteArrs.stream().mapToInt(arr -> arr.length).sum();
        byte[] fullArray = new byte[totalBytes];
        int currIndex = 0;
        for (byte[] arr2 : byteArrs) {
            System.arraycopy(arr2, 0, fullArray, currIndex, arr2.length);
            currIndex += arr2.length;
        }
        return fullArray;
    }

    public int numInts() {
        return 5;
    }

    public int numElements() {
        return 2 + tCommits.size() + productProof.getL().size() + productProof.getR().size();
    }
}
