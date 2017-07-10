package edu.stanford.cs.crypto.efficientct.commitments;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.ProofUtils;
import edu.stanford.cs.crypto.efficientct.linearalgebra.PeddersenBase;
import org.agrona.collections.CollectionUtil;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Collection;
import java.util.List;

/**
 * Created by buenz on 7/6/17.
 */
public class PolyCommittment {
    private final BigInteger zeroCoefficient;

    private final VectorX<PeddersenCommitment> coefficientCommitments;

    public PolyCommittment(BigInteger zeroCoefficient, VectorX<PeddersenCommitment> coefficientCommitments) {
        this.zeroCoefficient = zeroCoefficient;
        this.coefficientCommitments = coefficientCommitments;
    }


    public PeddersenCommitment evaluate(BigInteger x) {
        VectorX<BigInteger> xs = VectorX.iterate(coefficientCommitments.size(), x, x::multiply);
        PeddersenCommitment eval = xs.zip(coefficientCommitments, (xi, ci) -> ci.times(xi)).reduce(PeddersenCommitment::add).get();
        return eval.addConstant(zeroCoefficient);
    }

    public static PolyCommittment from(PeddersenBase base, VectorX<BigInteger> xs) {
        return new PolyCommittment(xs.get(0), xs.skip(1).map(x -> new PeddersenCommitment(base, x, ProofUtils.randomNumber())).materialize());
    }
    public VectorX<ECPoint> getCommitments(){
        return coefficientCommitments.map(PeddersenCommitment::getCommitment);
    }
}
