package edu.stanford.cs.crypto.efficientct.circuitproof;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.GeneratorParams;
import edu.stanford.cs.crypto.efficientct.algebra.BouncyCastleECPoint;
import edu.stanford.cs.crypto.efficientct.algebra.Group;
import edu.stanford.cs.crypto.efficientct.algebra.Secp256k1;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;
import edu.stanford.cs.crypto.efficientct.VerificationFailedException;
import edu.stanford.cs.crypto.efficientct.circuit.*;
import edu.stanford.cs.crypto.efficientct.commitments.PeddersenCommitment;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;
import org.junit.Test;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by buenz on 7/14/17.
 */
public class CircuitProofTest {
    private Group<BouncyCastleECPoint> group = new Secp256k1();

    @Test
    public void testMatrixVectorMult() throws VerificationFailedException {
        BigInteger q = group.groupOrder();
        int n = 16;
        FieldVector as = FieldVector.random(n, group.groupOrder());
        FieldVector bs = FieldVector.random(n, group.groupOrder());
        FieldVector out = as.hadamard(bs);
        GeneratorParams<BouncyCastleECPoint> params = GeneratorParams.generateParams(n, group);
        VectorX<FieldVector> zeros = VectorX.of(FieldVector.from(VectorX.fill(n, BigInteger.ZERO), q));
        PeddersenCommitment<BouncyCastleECPoint> uselessCommitment = new PeddersenCommitment<>(params.getBase(), BigInteger.ONE, BigInteger.ONE);
        VectorX<FieldVector> mZeros = VectorX.of(FieldVector.from(VectorX.of(BigInteger.ZERO), q));

        ArithmeticCircuit<BouncyCastleECPoint> circuit = new ArithmeticCircuit<BouncyCastleECPoint>(zeros, zeros, zeros, mZeros, VectorX.of(BigInteger.ZERO), GeneratorVector.from(VectorX.singleton(uselessCommitment.getCommitment()),group));
        CircuitProver<BouncyCastleECPoint> prover = new CircuitProver<>();
        VectorX<PeddersenCommitment<BouncyCastleECPoint>> of = VectorX.singleton(uselessCommitment);
        CircuitWitness<BouncyCastleECPoint> witness = new CircuitWitness<>(as, bs, out, of);
        CircuitProof<BouncyCastleECPoint> proof = prover.generateProof(params, circuit, witness);
        CircuitVerifier<BouncyCastleECPoint> verifier = new CircuitVerifier<>();
        verifier.verify(params, circuit, proof);
    }

    @Test
    public void testNormedProduct() throws VerificationFailedException {
        BigInteger q = group.groupOrder();

        int n = 16;
        FieldVector as = FieldVector.random(n, q);
        FieldVector bs = FieldVector.random(n, q);
        FieldVector out = as.hadamard(bs);
        GeneratorParams<BouncyCastleECPoint> params = GeneratorParams.generateParams(n, group);
        BigInteger randFact = BigInteger.ONE;
        PeddersenCommitment<BouncyCastleECPoint> aSum = new PeddersenCommitment<>(params.getBase(), as.sum().multiply(randFact));
        PeddersenCommitment<BouncyCastleECPoint> bSumHalf = new PeddersenCommitment<>(params.getBase(), bs.sum());

        VectorX<BigInteger> zeroVec = VectorX.fill(n, BigInteger.ZERO);
        VectorX<BigInteger> oneVec = VectorX.fill(n, BigInteger.ONE);

        VectorX<BigInteger> twoZeroOnes = VectorX.fill(n, BigInteger.ONE).prepend(BigInteger.ZERO, BigInteger.ZERO);
        VectorX<FieldVector> aCoeff = VectorX.of(FieldVector.from(oneVec, q), FieldVector.from(zeroVec, q));
        VectorX<FieldVector> bCoeff = VectorX.of(FieldVector.from(zeroVec, q), FieldVector.from(oneVec, q));
        VectorX<FieldVector> oCoeff = VectorX.of(FieldVector.from(zeroVec, q), FieldVector.from(zeroVec, q));
        VectorX<FieldVector> mOnes = VectorX.of(FieldVector.from(VectorX.of(randFact, BigInteger.ZERO), q), FieldVector.from(VectorX.of(BigInteger.ZERO, BigInteger.ONE), q));


        ArithmeticCircuit<BouncyCastleECPoint> circuit = new ArithmeticCircuit<>(aCoeff, bCoeff, oCoeff, mOnes, VectorX.of(BigInteger.ZERO), GeneratorVector.from(VectorX.of(aSum.getCommitment(), bSumHalf.getCommitment()), group));
        CircuitProver<BouncyCastleECPoint> prover = new CircuitProver<>();
        List<PeddersenCommitment<BouncyCastleECPoint>> list = new ArrayList<>(2);
        list.add(aSum);
        list.add(bSumHalf);
        CircuitWitness<BouncyCastleECPoint> witness = new CircuitWitness<>(as, bs, out, VectorX.fromIterable(list));
        CircuitProof<BouncyCastleECPoint> proof = prover.generateProof(params, circuit, witness);
        CircuitVerifier<BouncyCastleECPoint> verifier = new CircuitVerifier<>();
        verifier.verify(params, circuit, proof);
    }

    @Test
    public void testRangeProofCircuit() throws VerificationFailedException {
        BigInteger q = group.groupOrder();

        GeneratorParams<BouncyCastleECPoint> params = GeneratorParams.generateParams(8,group);

        PeddersenCommitment<BouncyCastleECPoint> commitment = new PeddersenCommitment<>(params.getBase(), BigInteger.TEN, ProofUtils.randomNumber());
        ArithmeticCircuit<BouncyCastleECPoint> circuit = RangeProofCircuit.createCircuit(8, commitment.getCommitment(),group);
        CircuitProver<BouncyCastleECPoint> prover = new CircuitProver<>();
        CircuitWitness<BouncyCastleECPoint> witness = RangeProofCircuit.fromRangeProofWittness(commitment, 8,group);

        CircuitProof<BouncyCastleECPoint> proof = prover.generateProof(params, circuit, witness);
        CircuitVerifier<BouncyCastleECPoint> verifier = new CircuitVerifier<>();
        CircuitNPVerifier<BouncyCastleECPoint> circuitNPVerifier = new CircuitNPVerifier<>();
        circuitNPVerifier.verify(null, circuit, witness);
        verifier.verify(params, circuit, proof);

    }

    @Test(expected = VerificationFailedException.class)
    public void testRangeProofSoundness() throws VerificationFailedException {

        GeneratorParams<BouncyCastleECPoint> params = GeneratorParams.generateParams(8,group);

        PeddersenCommitment<BouncyCastleECPoint> commitment = new PeddersenCommitment<>(params.getBase(), BigInteger.valueOf(256), ProofUtils.randomNumber());
        ArithmeticCircuit<BouncyCastleECPoint> circuit = RangeProofCircuit.createCircuit(8, commitment.getCommitment(),group);
        CircuitProver<BouncyCastleECPoint> prover = new CircuitProver<>();
        CircuitWitness<BouncyCastleECPoint> witness = RangeProofCircuit.fromRangeProofWittness(commitment, 8,group);

        CircuitProof<BouncyCastleECPoint> proof = prover.generateProof(params, circuit, witness);
        CircuitVerifier<BouncyCastleECPoint> verifier = new CircuitVerifier<>();
        verifier.verify(params, circuit, proof);

    }

}
