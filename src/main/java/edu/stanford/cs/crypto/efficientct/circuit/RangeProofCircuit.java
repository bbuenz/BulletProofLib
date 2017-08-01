package edu.stanford.cs.crypto.efficientct.circuit;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;

import java.math.BigInteger;
import java.security.spec.ECPoint;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by buenz on 7/14/17.
 */
public class RangeProofCircuit{
    public RangeProofCircuit(int numberOfBits, ECPoint commitment) {
        VectorX<BigInteger> zeros = VectorX.fill(numberOfBits + 1, BigInteger.ZERO);
        List<FieldVector> lWeights = new ArrayList<>(numberOfBits + 1);
        List<FieldVector> rWeights = new ArrayList<>(numberOfBits + 1);
        List<FieldVector> oWeights = new ArrayList<>(numberOfBits + 1);

        for (int i = 0; i < numberOfBits; ++i) {
            VectorX<BigInteger> bitOne = zeros.with(i, BigInteger.ONE);
            VectorX<BigInteger> bitNegOne = zeros.with(i, BigInteger.valueOf(-1));
            lWeights.add(FieldVector.from(bitOne));
            rWeights.add(FieldVector.from(bitNegOne));


        }
        VectorX<BigInteger> twoVector = VectorX.iterate(numberOfBits, BigInteger.ONE, bi -> bi.shiftLeft(1)).append(BigInteger.ZERO);

    }
}
