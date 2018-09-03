package edu.stanford.cs.crypto.efficientct.circuit;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.algebra.GroupElement;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;

import java.math.BigInteger;

/**
 * Created by buenz on 7/6/17.
 */
public class ArithmeticCircuit<T extends GroupElement<T>> {
    private final VectorX<FieldVector> lWeights;
    private final VectorX<FieldVector> rWeights;
    private final VectorX<FieldVector> oWeights;
    private final VectorX<FieldVector> commitmentWeights;

    private final VectorX<BigInteger> cs;
    private final GeneratorVector<T> commitments;

    public ArithmeticCircuit(VectorX<FieldVector> lWeights, VectorX<FieldVector> rWeights, VectorX<FieldVector> oWeights, VectorX<FieldVector> commitmentWeights, VectorX<BigInteger> cs, GeneratorVector<T> commitments) {
        this.lWeights = lWeights;
        this.rWeights = rWeights;
        this.oWeights = oWeights;
        this.commitmentWeights = commitmentWeights;
        this.cs = cs;
        this.commitments = commitments;
    }

    public VectorX<FieldVector> getlWeights() {
        return lWeights;
    }

    public VectorX<FieldVector> getrWeights() {
        return rWeights;
    }

    public VectorX<FieldVector> getoWeights() {
        return oWeights;
    }

    public VectorX<BigInteger> getCs() {
        return cs;
    }

    public GeneratorVector<T> getCommitments() {
        return commitments;
    }

    public VectorX<FieldVector> getCommitmentWeights() {
        return commitmentWeights;
    }
}
