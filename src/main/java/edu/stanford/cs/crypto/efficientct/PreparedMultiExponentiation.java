package edu.stanford.cs.crypto.efficientct;

import cyclops.stream.ReactiveSeq;
import edu.stanford.cs.crypto.efficientct.util.ECConstants;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.List;

/**
 * Created by buenz on 7/1/17.
 * Computes the multiexponentiation for a set of generators
 */
public class PreparedMultiExponentiation {
    public PreparedMultiExponentiation(List<ECPoint> generators) {
        this.generators = generators;
    }

    private final List<ECPoint> generators;

    /**
     * Computes \prod_{i=1}^n g_i^{e_i}
     */
    public ECPoint multiExp(List<BigInteger> exponents) {
        return ReactiveSeq.fromList(generators).zip(exponents, ECPoint::multiply).reduce(ECConstants.INFINITY, ECPoint::add);
    }
}
