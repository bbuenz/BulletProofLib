package edu.stanford.cs.crypto.efficientct.zetherprover;

import edu.stanford.cs.crypto.efficientct.Proof;
import edu.stanford.cs.crypto.efficientct.algebra.GroupElement;
import edu.stanford.cs.crypto.efficientct.innerproduct.ExtendedInnerProductProof;
import edu.stanford.cs.crypto.efficientct.innerproduct.InnerProductProof;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class ZetherProof<T extends GroupElement<T>> implements Proof {
    private final T aI;
    private final T s;
    private final T HL;
    private final T HR;
    private final GeneratorVector<T> tCommits;
    private final BigInteger t;
    private final BigInteger tauX;

    private final BigInteger mu;
    private final SigmaProof sigmaProof;
    private final ExtendedInnerProductProof<T> productProof;


    public ZetherProof(T aI, T s, T HL, T HR, GeneratorVector<T> tCommits, BigInteger t, BigInteger tauX, BigInteger mu, SigmaProof sigmaProof, ExtendedInnerProductProof<T> productProof) {
        this.aI = aI;
        this.s = s;
        this.HL = HL;
        this.HR = HR;
        this.tCommits = tCommits;
        this.t = t;
        this.tauX = tauX;
        this.mu = mu;
        this.sigmaProof = sigmaProof;
        this.productProof = productProof;
    }

    public T getaI() {
        return aI;
    }

    public T getS() {
        return s;
    }

    public T getHL() { return HL; }

    public T getHR() { return HR; }

    public BigInteger getT() {
        return t;
    }

    public BigInteger getTauX() {
        return tauX;
    }

    public BigInteger getMu() {
        return mu;
    }

    public GeneratorVector<T> gettCommits() {
        return tCommits;
    }


    public SigmaProof getSigmaProof() {
        return sigmaProof;
    }

    public ExtendedInnerProductProof<T> getProductProof() {
        return productProof;
    }


    @Override
    public byte[] serialize() {
        List<byte[]> byteArrs = new ArrayList<>();
        byteArrs.add(sigmaProof.serialize());
        byteArrs.add(productProof.serialize());
        byteArrs.add(aI.canonicalRepresentation());
        byteArrs.add(s.canonicalRepresentation());
        byteArrs.add(HL.canonicalRepresentation());
        byteArrs.add(HR.canonicalRepresentation());
        tCommits.stream().map(GroupElement::canonicalRepresentation).forEach(byteArrs::add);
        BigInteger q = tCommits.getGroup().groupOrder();
        byteArrs.add(t.mod(q).toByteArray()); // warning: this and the below might wind up shorter than you expect
        byteArrs.add(tauX.mod(q).toByteArray());
        byteArrs.add(mu.mod(q).toByteArray());
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


}
