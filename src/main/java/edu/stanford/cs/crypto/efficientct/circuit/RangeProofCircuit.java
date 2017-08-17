package edu.stanford.cs.crypto.efficientct.circuit;

import cyclops.collections.immutable.VectorX;
import cyclops.stream.ReactiveSeq;
import edu.stanford.cs.crypto.efficientct.commitments.PeddersenCommitment;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.PeddersenBase;
import edu.stanford.cs.crypto.efficientct.rangeproof.RangeProofWitness;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by buenz on 7/14/17.
 */
public class RangeProofCircuit {
    public static ArithmeticCircuit createCircuit(int numberOfBits, ECPoint commitment) {
        VectorX<BigInteger> zeros = VectorX.fill(numberOfBits, BigInteger.ZERO);

        List<FieldVector> lWeights = new ArrayList<>(numberOfBits * 2 + 1);
        List<FieldVector> rWeights = new ArrayList<>(numberOfBits * 2 + 1);
        List<FieldVector> oWeights = new ArrayList<>(numberOfBits * 2 + 1);
        List<FieldVector> vWeights = new ArrayList<>(numberOfBits * 2 + 1);

        List<BigInteger> cs = new ArrayList<>();
        FieldVector zeroVector = FieldVector.from(zeros);
        for (int i = 0; i < numberOfBits; ++i) {
            VectorX<BigInteger> bitOne = zeros.with(i, BigInteger.ONE);
            VectorX<BigInteger> bitNegOne = zeros.with(i, BigInteger.valueOf(-1));
            lWeights.add(FieldVector.from(bitOne));
            rWeights.add(FieldVector.from(bitNegOne));
            oWeights.add(zeroVector);
            vWeights.add(FieldVector.from(VectorX.of(BigInteger.ZERO)));
            cs.add(BigInteger.ONE);

        }
        for (int i = 0; i < numberOfBits; ++i) {
            lWeights.add(zeroVector);
            rWeights.add(zeroVector);
            VectorX<BigInteger> bitNegOne = zeros.with(i, BigInteger.valueOf(-1));
            oWeights.add(FieldVector.from(bitNegOne));
            vWeights.add(FieldVector.from(VectorX.of(BigInteger.ZERO)));
            cs.add(BigInteger.ZERO);

        }
        lWeights.add(FieldVector.pow(BigInteger.valueOf(2), numberOfBits));
        rWeights.add(zeroVector);
        oWeights.add(zeroVector);
        vWeights.add(FieldVector.from(VectorX.of(BigInteger.ONE)));
        cs.add(BigInteger.ZERO);
        return new ArithmeticCircuit(VectorX.fromIterable(lWeights), VectorX.fromIterable(rWeights), VectorX.fromIterable(oWeights), VectorX.fromIterable(vWeights), VectorX.fromIterable(cs), GeneratorVector.from(VectorX.of(commitment)));

    }

    public static CircuitWitness fromRangeProofWittness(PeddersenCommitment witness, int bits) {
        FieldVector a = FieldVector.from(VectorX.range(0, bits).map(witness.getX()::testBit).map(b -> b ? BigInteger.ONE : BigInteger.ZERO));
        FieldVector b = a.add(BigInteger.valueOf(-1));
        FieldVector out = FieldVector.from(VectorX.fill(bits,BigInteger.ZERO));
        return new CircuitWitness(a, b, out, VectorX.of(witness));

    }
}
