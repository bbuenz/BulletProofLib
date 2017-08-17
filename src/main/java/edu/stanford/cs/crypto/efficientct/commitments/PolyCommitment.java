package edu.stanford.cs.crypto.efficientct.commitments;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;
import edu.stanford.cs.crypto.efficientct.linearalgebra.PeddersenBase;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

/**
 * Created by buenz on 7/6/17.
 */
public class PolyCommitment {

    private final VectorX<PeddersenCommitment> coefficientCommitments;

    public PolyCommitment(VectorX<PeddersenCommitment> coefficientCommitments) {
        this.coefficientCommitments = coefficientCommitments;
    }


    public PeddersenCommitment evaluate(BigInteger x) {

        return VectorX.iterate(coefficientCommitments.size(), BigInteger.ONE, x::multiply).zip(coefficientCommitments, (xi, ci) -> ci.times(xi)).reduce(PeddersenCommitment::add).get();
    }

    public VectorX<PeddersenCommitment> getCoefficientCommitments() {
        return coefficientCommitments;
    }

    public VectorX<ECPoint> getCommitments() {
        return coefficientCommitments.filterNot(pc -> pc.getR().equals(BigInteger.ZERO)).map(PeddersenCommitment::getCommitment);
    }

    public static PolyCommitment from(PeddersenBase base, BigInteger x0, VectorX<BigInteger> xs) {
        VectorX<PeddersenCommitment> peddersenCommitments = xs.map(x -> new PeddersenCommitment(base, x, ProofUtils.randomNumber())).prepend(new PeddersenCommitment(base, x0, BigInteger.ZERO)).materialize();
        return new PolyCommitment(peddersenCommitments);
    }
}
