package edu.stanford.cs.crypto.efficientct.circuitproof;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.GeneratorParams;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;
import edu.stanford.cs.crypto.efficientct.VerificationFailedException;
import edu.stanford.cs.crypto.efficientct.circuit.*;
import edu.stanford.cs.crypto.efficientct.commitments.PeddersenCommitment;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;
import org.junit.Test;

import java.math.BigInteger;

/**
 * Created by buenz on 7/14/17.
 */
public class CircuitProofTest {
    @Test
    public void testMatrixVectorMult() throws VerificationFailedException {
        int n = 16;
        FieldVector as = FieldVector.random(n);
        FieldVector bs = FieldVector.random(n);
        FieldVector out = as.hadamard(bs);
        GeneratorParams params = GeneratorParams.generateParams(n);
        VectorX<FieldVector> zeros = VectorX.of(FieldVector.from(VectorX.fill(n, BigInteger.ZERO)));
        PeddersenCommitment uselessCommitment = new PeddersenCommitment(params.getBase(), BigInteger.ONE, BigInteger.ONE);
        VectorX<FieldVector> mZeros = VectorX.of(FieldVector.from(VectorX.of(BigInteger.ZERO)));

        ArithmeticCircuit circuit = new ArithmeticCircuit(zeros, zeros, zeros, mZeros, VectorX.of(BigInteger.ZERO), GeneratorVector.from(VectorX.of(uselessCommitment.getCommitment())));
        CircuitProver prover = new CircuitProver();
        CircuitWitness witness = new CircuitWitness(as, bs, out, VectorX.of(uselessCommitment));
        CircuitProof proof = prover.generateProof(params, circuit, witness);
        CircuitVerifier verifier = new CircuitVerifier();
        verifier.verify(params, circuit, proof);
    }

    @Test
    public void testNormedProduct() throws VerificationFailedException {
        int n = 16;
        FieldVector as = FieldVector.random(n);
        FieldVector bs = FieldVector.random(n);
        FieldVector out = as.hadamard(bs);
        GeneratorParams params = GeneratorParams.generateParams(n);
        BigInteger randFact = BigInteger.ONE;
        PeddersenCommitment aSum = new PeddersenCommitment(params.getBase(), as.sum().multiply(randFact));
        PeddersenCommitment bSumHalf = new PeddersenCommitment(params.getBase(), bs.sum());

        VectorX<BigInteger> zeroVec = VectorX.fill(n, BigInteger.ZERO);
        VectorX<BigInteger> oneVec = VectorX.fill(n, BigInteger.ONE);

        VectorX<BigInteger> twoZeroOnes = VectorX.fill(n, BigInteger.ONE).prepend(BigInteger.ZERO, BigInteger.ZERO);
        VectorX<FieldVector> aCoeff = VectorX.of(FieldVector.from(oneVec), FieldVector.from(zeroVec));
        VectorX<FieldVector> bCoeff = VectorX.of(FieldVector.from(zeroVec), FieldVector.from(oneVec));
        VectorX<FieldVector> oCoeff = VectorX.of(FieldVector.from(zeroVec), FieldVector.from(zeroVec));
        VectorX<FieldVector> mOnes = VectorX.of(FieldVector.from(VectorX.of(randFact, BigInteger.ZERO)), FieldVector.from(VectorX.of(BigInteger.ZERO, BigInteger.ONE)));


        ArithmeticCircuit circuit = new ArithmeticCircuit(aCoeff, bCoeff, oCoeff, mOnes, VectorX.of(BigInteger.ZERO), GeneratorVector.from(VectorX.of(aSum.getCommitment(), bSumHalf.getCommitment())));
        CircuitProver prover = new CircuitProver();
        CircuitWitness witness = new CircuitWitness(as, bs, out, VectorX.of(aSum, bSumHalf));
        CircuitProof proof = prover.generateProof(params, circuit, witness);
        CircuitVerifier verifier = new CircuitVerifier();
        verifier.verify(params, circuit, proof);
    }

    @Test
    public void testRangeProofCircuit() throws VerificationFailedException {
        GeneratorParams params = GeneratorParams.generateParams(8);

        PeddersenCommitment commitment = new PeddersenCommitment(params.getBase(), BigInteger.TEN, ProofUtils.randomNumber());
        ArithmeticCircuit circuit = RangeProofCircuit.createCircuit(8, commitment.getCommitment());
        CircuitProver prover = new CircuitProver();
        CircuitWitness witness = RangeProofCircuit.fromRangeProofWittness(commitment, 8);

        CircuitProof proof = prover.generateProof(params, circuit, witness);
        CircuitVerifier verifier = new CircuitVerifier();
        new CircuitNPVerifier().verify(null,circuit,witness);
        verifier.verify(params, circuit, proof);

    }
    @Test(expected = VerificationFailedException.class)
    public void testRangeProofSoundness() throws VerificationFailedException {
        GeneratorParams params = GeneratorParams.generateParams(8);

        PeddersenCommitment commitment = new PeddersenCommitment(params.getBase(), BigInteger.valueOf(256), ProofUtils.randomNumber());
        ArithmeticCircuit circuit = RangeProofCircuit.createCircuit(8, commitment.getCommitment());
        CircuitProver prover = new CircuitProver();
        CircuitWitness witness = RangeProofCircuit.fromRangeProofWittness(commitment, 8);

        CircuitProof proof = prover.generateProof(params, circuit, witness);
        CircuitVerifier verifier = new CircuitVerifier();
        verifier.verify(params, circuit, proof);

    }

}
