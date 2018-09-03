package edu.stanford.cs.crypto.efficientct.circuit;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.algebra.Group;
import edu.stanford.cs.crypto.efficientct.algebra.GroupElement;
import edu.stanford.cs.crypto.efficientct.commitments.PeddersenCommitment;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by buenz on 7/14/17.
 */
public class RangeProofCircuit {
    public static <T extends GroupElement<T>> ArithmeticCircuit<T> createCircuit(int numberOfBits, T commitment, Group<T> group) {
        BigInteger q = group.groupOrder();
        VectorX<BigInteger> zeros = VectorX.fill(numberOfBits, BigInteger.ZERO);

        List<FieldVector> lWeights = new ArrayList<>(numberOfBits * 2 + 1);
        List<FieldVector> rWeights = new ArrayList<>(numberOfBits * 2 + 1);
        List<FieldVector> oWeights = new ArrayList<>(numberOfBits * 2 + 1);
        List<FieldVector> vWeights = new ArrayList<>(numberOfBits * 2 + 1);

        List<BigInteger> cs = new ArrayList<>();
        FieldVector zeroVector = FieldVector.from(zeros, q);
        for (int i = 0; i < numberOfBits; ++i) {
            VectorX<BigInteger> bitOne = zeros.with(i, BigInteger.ONE);
            VectorX<BigInteger> bitNegOne = zeros.with(i, BigInteger.valueOf(-1));
            lWeights.add(FieldVector.from(bitOne, q));
            rWeights.add(FieldVector.from(bitNegOne, q));
            oWeights.add(zeroVector);
            vWeights.add(FieldVector.from(VectorX.of(BigInteger.ZERO), q));
            cs.add(BigInteger.ONE);

        }
        for (int i = 0; i < numberOfBits; ++i) {
            lWeights.add(zeroVector);
            rWeights.add(zeroVector);
            VectorX<BigInteger> bitNegOne = zeros.with(i, BigInteger.valueOf(-1));
            oWeights.add(FieldVector.from(bitNegOne, q));
            vWeights.add(FieldVector.from(VectorX.of(BigInteger.ZERO), q));
            cs.add(BigInteger.ZERO);

        }
        lWeights.add(FieldVector.pow(BigInteger.valueOf(2), numberOfBits, q));
        rWeights.add(zeroVector);
        oWeights.add(zeroVector);
        vWeights.add(FieldVector.from(VectorX.of(BigInteger.ONE), q));
        cs.add(BigInteger.ZERO);

        return new ArithmeticCircuit<>(VectorX.fromIterable(lWeights), VectorX.fromIterable(rWeights), VectorX.fromIterable(oWeights), VectorX.fromIterable(vWeights), VectorX.fromIterable(cs), new GeneratorVector<>(VectorX.singleton(commitment), group));

    }

    public static <T extends GroupElement<T>> CircuitWitness<T> fromRangeProofWittness(PeddersenCommitment<T> witness, int bits, Group<T> group) {
        FieldVector a = FieldVector.from(VectorX.range(0, bits).map(witness.getX()::testBit).map(b -> b ? BigInteger.ONE : BigInteger.ZERO), group.groupOrder());
        FieldVector b = a.add(BigInteger.valueOf(-1));
        FieldVector out = FieldVector.from(VectorX.fill(bits, BigInteger.ZERO), group.groupOrder());
        return new CircuitWitness<>(a, b, out, VectorX.singleton(witness));

    }
}
