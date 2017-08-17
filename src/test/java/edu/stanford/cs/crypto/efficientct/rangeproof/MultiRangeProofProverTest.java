package edu.stanford.cs.crypto.efficientct.rangeproof;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.GeneratorParams;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;
import edu.stanford.cs.crypto.efficientct.VerificationFailedException;
import edu.stanford.cs.crypto.efficientct.commitments.PeddersenCommitment;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.PeddersenBase;
import edu.stanford.cs.crypto.efficientct.multirangeproof.MultiRangeProofProver;
import edu.stanford.cs.crypto.efficientct.multirangeproof.MultiRangeProofSystem;
import edu.stanford.cs.crypto.efficientct.multirangeproof.MultiRangeProofVerifier;
import org.junit.Test;

import java.math.BigInteger;


/**
 * Created by buenz on 7/1/17.
 */
public class MultiRangeProofProverTest {
    @Test
    public void testCompletness() throws VerificationFailedException {

        GeneratorParams parameters = GeneratorParams.generateParams(16);

        PeddersenBase base = parameters.getBase();
        VectorX<PeddersenCommitment> witness = VectorX.of(BigInteger.valueOf(3), BigInteger.valueOf(123)).map(x -> new PeddersenCommitment(base, x)).materialize();
        GeneratorVector commitments = GeneratorVector.from(witness.map(PeddersenCommitment::getCommitment));
        RangeProof proof = new MultiRangeProofProver().generateProof(parameters, commitments, witness);
        MultiRangeProofVerifier verifier = new MultiRangeProofVerifier();
        verifier.verify(parameters, commitments, proof);
    }

    @Test(expected = VerificationFailedException.class)
    public void testSoundness() throws VerificationFailedException {

        GeneratorParams parameters = GeneratorParams.generateParams(16);

        PeddersenBase base = parameters.getBase();
        VectorX<PeddersenCommitment> witness = VectorX.of(BigInteger.valueOf(3), BigInteger.valueOf(256)).map(x -> new PeddersenCommitment(base, x)).materialize();
        GeneratorVector commitments = GeneratorVector.from(witness.map(PeddersenCommitment::getCommitment));
        RangeProof proof = new MultiRangeProofProver().generateProof(parameters, commitments, witness);
        MultiRangeProofVerifier verifier = new MultiRangeProofVerifier();
        verifier.verify(parameters, commitments, proof);

    }

    @Test
    public void testAgainstSingleProof() throws VerificationFailedException {


        GeneratorParams parameters = GeneratorParams.generateParams(64);
        PeddersenBase base = parameters.getBase();
        VectorX<PeddersenCommitment> witness = VectorX.of(new PeddersenCommitment(base, BigInteger.valueOf(123))).materialize();
        GeneratorVector commitments = GeneratorVector.from(witness.map(PeddersenCommitment::getCommitment));
        RangeProof proof = new MultiRangeProofProver().generateProof(parameters, commitments, witness);
        RangeProof singlePRoof = new RangeProofProver().generateProof(parameters, commitments.get(0), witness.get(0));
        RangeProofVerifier verifier = new RangeProofVerifier();
        verifier.verify(parameters, commitments.get(0), singlePRoof);

        verifier.verify(parameters, commitments.get(0), proof);
        MultiRangeProofVerifier multiRangeProofVerifier = new MultiRangeProofVerifier();
        multiRangeProofVerifier.verify(parameters, commitments, proof);
        multiRangeProofVerifier.verify(parameters, commitments, singlePRoof);
        System.out.println(proof.serialize().length);

    }

    @Test
    public void testAgainstSingleProof100Times() throws VerificationFailedException {
        MultiRangeProofSystem system = new MultiRangeProofSystem();
        GeneratorParams parameters = GeneratorParams.generateParams(16);
        PeddersenBase base = parameters.getBase();
        for (int i = 0; i < 100; ++i) {
            VectorX<PeddersenCommitment> witness = VectorX.of(new PeddersenCommitment(base, ProofUtils.randomNumber(8))).materialize();
            GeneratorVector commitments = GeneratorVector.from(witness.map(PeddersenCommitment::getCommitment));
            RangeProof proof = new MultiRangeProofProver().generateProof(parameters, commitments, witness);
            RangeProof singlePRoof = new RangeProofProver().generateProof(parameters, commitments.get(0), witness.get(0));
            RangeProofVerifier verifier = new RangeProofVerifier();
            verifier.verify(parameters, commitments.get(0), singlePRoof);

            verifier.verify(parameters, commitments.get(0), proof);
            MultiRangeProofVerifier multiRangeProofVerifier = new MultiRangeProofVerifier();
            multiRangeProofVerifier.verify(parameters, commitments, proof);
            multiRangeProofVerifier.verify(parameters, commitments, singlePRoof);

        }
    }

    @Test
    public void testSixTeenProofs() throws VerificationFailedException {
        MultiRangeProofSystem system = new MultiRangeProofSystem();

        GeneratorParams parameters = GeneratorParams.generateParams(1024);

        VectorX<PeddersenCommitment> witness = VectorX.generate(16, () -> ProofUtils.randomNumber(60)).map(x->new PeddersenCommitment(parameters.getBase(),x)).materialize();


        GeneratorVector commitments = GeneratorVector.from(witness.map(PeddersenCommitment::getCommitment));
        RangeProof rangeProof = new MultiRangeProofProver().generateProof(parameters, commitments, witness);
        System.out.println(rangeProof.serialize().length);
        System.out.println(rangeProof.numInts());
        System.out.println(rangeProof.numElements());
        System.out.println(32 * (rangeProof.numElements() + rangeProof.numInts()));
        System.out.println(32 * (rangeProof.numElements() + rangeProof.numInts()) + rangeProof.numElements());

        new MultiRangeProofVerifier().verify(parameters, commitments, rangeProof);

    }

    @Test
    public void testSix() throws VerificationFailedException {
        MultiRangeProofSystem system = new MultiRangeProofSystem();

        GeneratorParams parameters = GeneratorParams.generateParams(384);
        VectorX<PeddersenCommitment> witness = VectorX.generate(6, () -> ProofUtils.randomNumber(60)).map(x->new PeddersenCommitment(parameters.getBase(),x)).materialize();


        GeneratorVector commitments = GeneratorVector.from(witness.map(PeddersenCommitment::getCommitment));
        RangeProof rangeProof = new MultiRangeProofProver().generateProof(parameters, commitments, witness);
        System.out.println(rangeProof.serialize().length);
        new MultiRangeProofVerifier().verify(parameters, commitments, rangeProof);

    }

    @Test
    public void testTwo() throws VerificationFailedException {
        MultiRangeProofSystem system = new MultiRangeProofSystem();

        GeneratorParams parameters = GeneratorParams.generateParams(128);
        VectorX<PeddersenCommitment> witness = VectorX.generate(2, () -> ProofUtils.randomNumber(60)).map(x->new PeddersenCommitment(parameters.getBase(),x)).materialize();


        GeneratorVector commitments = GeneratorVector.from(witness.map(PeddersenCommitment::getCommitment));
        RangeProof rangeProof = new MultiRangeProofProver().generateProof(parameters, commitments, witness);        System.out.println(rangeProof.serialize().length);
        new MultiRangeProofVerifier().verify(parameters, commitments, rangeProof);

    }


}