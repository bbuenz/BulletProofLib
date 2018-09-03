package edu.stanford.cs.crypto.efficientct.rangeproof;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.GeneratorParams;
import edu.stanford.cs.crypto.efficientct.algebra.BouncyCastleCurve;
import edu.stanford.cs.crypto.efficientct.algebra.BouncyCastleECPoint;
import edu.stanford.cs.crypto.efficientct.algebra.Secp256k1;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;
import edu.stanford.cs.crypto.efficientct.VerificationFailedException;
import edu.stanford.cs.crypto.efficientct.commitments.PeddersenCommitment;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.PeddersenBase;
import edu.stanford.cs.crypto.efficientct.multirangeproof.MultiRangeProofProver;
import edu.stanford.cs.crypto.efficientct.multirangeproof.MultiRangeProofVerifier;
import org.junit.Test;

import java.math.BigInteger;


/**
 * Created by buenz on 7/1/17.
 */
public class MultiRangeProofProverTest {
    BouncyCastleCurve curve = new Secp256k1();

    @Test
    public void testCompletness() throws VerificationFailedException {

        GeneratorParams<BouncyCastleECPoint> parameters = GeneratorParams.generateParams(16, curve);

        PeddersenBase<BouncyCastleECPoint> base = parameters.getBase();
        VectorX<PeddersenCommitment<BouncyCastleECPoint>> witness = VectorX.of(BigInteger.valueOf(3), BigInteger.valueOf(123)).map(x -> new PeddersenCommitment<>(base, x)).materialize();
        GeneratorVector<BouncyCastleECPoint> commitments = GeneratorVector.from(witness.map(PeddersenCommitment::getCommitment), curve);
        RangeProof<BouncyCastleECPoint> proof = new MultiRangeProofProver<BouncyCastleECPoint>().generateProof(parameters, commitments, witness);
        MultiRangeProofVerifier<BouncyCastleECPoint> verifier = new MultiRangeProofVerifier<>();
        verifier.verify(parameters, commitments, proof);
    }

    @Test(expected = VerificationFailedException.class)
    public void testSoundness() throws VerificationFailedException {
        GeneratorParams<BouncyCastleECPoint> parameters = GeneratorParams.generateParams(16, curve);

        PeddersenBase<BouncyCastleECPoint> base = parameters.getBase();
        VectorX<PeddersenCommitment<BouncyCastleECPoint>> witness = VectorX.of(BigInteger.valueOf(3), BigInteger.valueOf(256)).map(x -> new PeddersenCommitment<>(base, x)).materialize();
        GeneratorVector<BouncyCastleECPoint> commitments = GeneratorVector.from(witness.map(PeddersenCommitment::getCommitment), curve);
        RangeProof<BouncyCastleECPoint> proof = new MultiRangeProofProver<BouncyCastleECPoint>().generateProof(parameters, commitments, witness);
        MultiRangeProofVerifier<BouncyCastleECPoint> verifier = new MultiRangeProofVerifier<>();
        verifier.verify(parameters, commitments, proof);

    }

    @Test
    public void testAgainstSingleProof() throws VerificationFailedException {
        GeneratorParams<BouncyCastleECPoint> parameters = GeneratorParams.generateParams(64, curve);

        PeddersenBase<BouncyCastleECPoint> base = parameters.getBase();
        VectorX<PeddersenCommitment<BouncyCastleECPoint>> witness = VectorX.of( BigInteger.valueOf(123)).map(x -> new PeddersenCommitment<>(base, x)).materialize();
        GeneratorVector<BouncyCastleECPoint> commitments = GeneratorVector.from(witness.map(PeddersenCommitment::getCommitment), curve);
        RangeProof<BouncyCastleECPoint> proof = new MultiRangeProofProver<BouncyCastleECPoint>().generateProof(parameters, commitments, witness);
        RangeProof<BouncyCastleECPoint> singlePRoof = new RangeProofProver<BouncyCastleECPoint>().generateProof(parameters, commitments.get(0), witness.get(0));
        RangeProofVerifier<BouncyCastleECPoint> verifier = new RangeProofVerifier<>();
        verifier.verify(parameters, commitments.get(0), singlePRoof);

        verifier.verify(parameters, commitments.get(0), proof);
        MultiRangeProofVerifier<BouncyCastleECPoint> multiRangeProofVerifier = new MultiRangeProofVerifier<>();
        multiRangeProofVerifier.verify(parameters, commitments, proof);
        multiRangeProofVerifier.verify(parameters, commitments, singlePRoof);
        System.out.println(proof.serialize().length);

    }

    @Test
    public void testAgainstSingleProof100Times() throws VerificationFailedException {

        GeneratorParams<BouncyCastleECPoint> parameters = GeneratorParams.generateParams(16, curve);

        PeddersenBase<BouncyCastleECPoint> base = parameters.getBase();
        for (int i = 0; i < 100; ++i) {
            VectorX<PeddersenCommitment<BouncyCastleECPoint>> witness = VectorX.of( BigInteger.valueOf(123)).map(x -> new PeddersenCommitment<>(base, x)).materialize();
            GeneratorVector<BouncyCastleECPoint> commitments = GeneratorVector.from(witness.map(PeddersenCommitment::getCommitment), curve);
            RangeProof<BouncyCastleECPoint> proof = new MultiRangeProofProver<BouncyCastleECPoint>().generateProof(parameters, commitments, witness);
            RangeProof<BouncyCastleECPoint> singlePRoof = new RangeProofProver<BouncyCastleECPoint>().generateProof(parameters, commitments.get(0), witness.get(0));
            RangeProofVerifier<BouncyCastleECPoint> verifier = new RangeProofVerifier<>();
            verifier.verify(parameters, commitments.get(0), singlePRoof);

            verifier.verify(parameters, commitments.get(0), proof);
            MultiRangeProofVerifier<BouncyCastleECPoint> multiRangeProofVerifier = new MultiRangeProofVerifier<>();
            multiRangeProofVerifier.verify(parameters, commitments, proof);
            multiRangeProofVerifier.verify(parameters, commitments, singlePRoof);
        }


    }

    @Test
    public void testSixTeenProofs() throws VerificationFailedException {

        GeneratorParams<BouncyCastleECPoint> parameters = GeneratorParams.generateParams(1024, curve);

        VectorX<PeddersenCommitment<BouncyCastleECPoint>> witness = VectorX.generate(16, () -> ProofUtils.randomNumber(60)).map(x -> new PeddersenCommitment<>(parameters.getBase(), x)).materialize();
        GeneratorVector<BouncyCastleECPoint> commitments = GeneratorVector.from(witness.map(PeddersenCommitment::getCommitment), curve);
        RangeProof<BouncyCastleECPoint> rangeProof = new MultiRangeProofProver<BouncyCastleECPoint>().generateProof(parameters, commitments, witness);


        System.out.println(rangeProof.serialize().length);
        System.out.println(rangeProof.numInts());
        System.out.println(rangeProof.numElements());
        System.out.println(32 * (rangeProof.numElements() + rangeProof.numInts()));
        System.out.println(32 * (rangeProof.numElements() + rangeProof.numInts()) + rangeProof.numElements());

        new MultiRangeProofVerifier<BouncyCastleECPoint>().verify(parameters, commitments, rangeProof);

    }

    @Test
    public void testSix() throws VerificationFailedException {
        GeneratorParams<BouncyCastleECPoint> parameters = GeneratorParams.generateParams(384, curve);

        VectorX<PeddersenCommitment<BouncyCastleECPoint>> witness = VectorX.generate(6, () -> ProofUtils.randomNumber(60)).map(x -> new PeddersenCommitment<>(parameters.getBase(), x)).materialize();
        GeneratorVector<BouncyCastleECPoint> commitments = GeneratorVector.from(witness.map(PeddersenCommitment::getCommitment), curve);
        RangeProof<BouncyCastleECPoint> rangeProof = new MultiRangeProofProver<BouncyCastleECPoint>().generateProof(parameters, commitments, witness);
        System.out.println(rangeProof.serialize().length);

        new MultiRangeProofVerifier<BouncyCastleECPoint>().verify(parameters, commitments, rangeProof);


    }

    @Test
    public void testTwo() throws VerificationFailedException {
        GeneratorParams<BouncyCastleECPoint> parameters = GeneratorParams.generateParams(128, curve);

        VectorX<PeddersenCommitment<BouncyCastleECPoint>> witness = VectorX.generate(2, () -> ProofUtils.randomNumber(60)).map(x -> new PeddersenCommitment<>(parameters.getBase(), x)).materialize();
        GeneratorVector<BouncyCastleECPoint> commitments = GeneratorVector.from(witness.map(PeddersenCommitment::getCommitment), curve);
        RangeProof<BouncyCastleECPoint> rangeProof = new MultiRangeProofProver<BouncyCastleECPoint>().generateProof(parameters, commitments, witness);
        System.out.println(rangeProof.serialize().length);

        new MultiRangeProofVerifier<BouncyCastleECPoint>().verify(parameters, commitments, rangeProof);
    }


}