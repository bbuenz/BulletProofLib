package edu.stanford.cs.crypto.efficientct.innerproduct;

import edu.stanford.cs.crypto.efficientct.algebra.GroupElement;

import java.math.BigInteger;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

/**
 * Created by buenz on 6/28/17.
 */
public class ExtendedInnerProductProof<T extends GroupElement<T>> extends InnerProductProof<T> {
    private final List<BigInteger> as;
    private final List<BigInteger> bs;


    public ExtendedInnerProductProof(List<T> l, List<T> r, List<BigInteger> as, List<BigInteger> bs) {
        super(l, r, as.get(as.size() - 1), bs.get(bs.size() - 1));
        this.as = as;
        this.bs = bs;
    }

    public List<BigInteger> getAs() {
        return as;
    }

    public List<BigInteger> getBs() {
        return bs;
    }

    @Override
    public byte[] serialize() {
        Stream<byte[]> groupElStream = Stream.concat(getL().stream(), getR().stream()).map(GroupElement::canonicalRepresentation);
        Stream<byte[]> elementStream = Stream.concat(as.stream(), bs.stream()).map(BigInteger::toByteArray);
        List<byte[]> byteArrs = Stream.concat(groupElStream, elementStream).collect(Collectors.toList());
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
