package edu.stanford.cs.crypto.efficientct.rangeproof;

import edu.stanford.cs.crypto.efficientct.ECConstants;
import edu.stanford.cs.crypto.efficientct.Proof;
import edu.stanford.cs.crypto.efficientct.innerproduct.InnerProductProof;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by buenz on 7/1/17.
 */
public class RangeProof implements Proof {
    private final ECPoint aI;
    private final ECPoint s;
    private final GeneratorVector tCommits;
    private final BigInteger tauX;
    private final BigInteger mu;
    private final BigInteger t;
    private final InnerProductProof productProof;

    public RangeProof(ECPoint aI, ECPoint s, GeneratorVector tCommits, BigInteger tauX, BigInteger mu, BigInteger t, InnerProductProof productProof) {
        this.aI = aI;
        this.s = s;
        this.tCommits = tCommits;
        this.tauX = tauX;
        this.mu = mu;
        this.t = t;
        this.productProof = productProof;
    }

    public ECPoint getaI() {
        return aI;
    }

    public ECPoint getS() {
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

    public InnerProductProof getProductProof() {
        return productProof;
    }

    public GeneratorVector gettCommits() {
        return tCommits;
    }

    @Override
    public byte[] serialize() {
        List<byte[]> byteArrs = new ArrayList<>();
        byteArrs.add(productProof.serialize());
        byteArrs.add(aI.getEncoded(true));
        byteArrs.add(s.getEncoded(true));
        tCommits.stream().map(p -> p.getEncoded(true)).forEach(byteArrs::add);
        byteArrs.add(tauX.mod(ECConstants.P).toByteArray());
        byteArrs.add(mu.mod(ECConstants.P).toByteArray());
        byteArrs.add(t.mod(ECConstants.P).toByteArray());

        int totalBytes = byteArrs.stream().mapToInt(arr -> arr.length).sum();
        byte[] fullArray = new byte[totalBytes];
        int currIndex = 0;
        for (byte[] arr2 : byteArrs) {
            System.arraycopy(arr2, 0, fullArray, currIndex, arr2.length);
            currIndex += arr2.length;
        }
        return fullArray;
    }
    public int numInts(){
        return 5;
    }
    public int numElements(){
        return 2+ tCommits.size()+productProof.getL().size()+productProof.getR().size();
    }
}
