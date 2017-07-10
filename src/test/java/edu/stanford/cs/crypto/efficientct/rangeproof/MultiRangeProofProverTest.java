package edu.stanford.cs.crypto.efficientct.rangeproof;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.GeneratorParams;
import edu.stanford.cs.crypto.efficientct.ProofUtils;
import edu.stanford.cs.crypto.efficientct.VerificationFailedException;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.PeddersenBase;
import edu.stanford.cs.crypto.efficientct.multirangeproof.MultiRangeProofProver;
import edu.stanford.cs.crypto.efficientct.multirangeproof.MultiRangeProofSystem;
import edu.stanford.cs.crypto.efficientct.multirangeproof.MultiRangeProofVerifier;
import edu.stanford.cs.crypto.efficientct.multirangeproof.MultiRangeProofWitness;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Test;

import java.math.BigInteger;


/**
 * Created by buenz on 7/1/17.
 */
public class MultiRangeProofProverTest {
    @Test
    public void testCompletness() throws VerificationFailedException {
        VectorX<BigInteger> numbers = VectorX.of(BigInteger.valueOf(3), BigInteger.valueOf(123));
        VectorX<BigInteger> randomness = VectorX.generate(2, ProofUtils::randomNumber).materialize();


        MultiRangeProofSystem system = new MultiRangeProofSystem();

        GeneratorParams parameters = system.generateParams(16);
        PeddersenBase base = parameters.getBase();
        GeneratorVector commitments = GeneratorVector.from(numbers.zip(randomness, base::commit));
        MultiRangeProofWitness witness = new MultiRangeProofWitness(numbers, randomness);
        RangeProof proof = new MultiRangeProofProver().generateProof(parameters, commitments, witness);
        MultiRangeProofVerifier verifier = new MultiRangeProofVerifier();
        verifier.verify(parameters, commitments, proof);
    }

    @Test(expected = VerificationFailedException.class)
    public void testSoundness() throws VerificationFailedException {
        VectorX<BigInteger> numbers = VectorX.of(BigInteger.valueOf(3), BigInteger.valueOf(256));
        VectorX<BigInteger> randomness = VectorX.generate(2, ProofUtils::randomNumber).materialize();


        MultiRangeProofSystem system = new MultiRangeProofSystem();

        GeneratorParams parameters = system.generateParams(16);
        PeddersenBase base = parameters.getBase();
        GeneratorVector commitments = GeneratorVector.from(numbers.zip(randomness, base::commit));
        MultiRangeProofWitness witness = new MultiRangeProofWitness(numbers, randomness);
        RangeProof proof = new MultiRangeProofProver().generateProof(parameters, commitments, witness);
        MultiRangeProofVerifier verifier = new MultiRangeProofVerifier();
        verifier.verify(parameters, commitments, proof);
    }

    @Test
    public void testAgainstSingleProof() throws VerificationFailedException {
        VectorX<BigInteger> numbers = VectorX.of(BigInteger.valueOf(123));
        VectorX<BigInteger> randomness = VectorX.of(ProofUtils.randomNumber());


        MultiRangeProofSystem system = new MultiRangeProofSystem();

        GeneratorParams parameters = system.generateParams(16);
        PeddersenBase base = parameters.getBase();
        GeneratorVector commitments = GeneratorVector.from(numbers.zip(randomness, base::commit));
        MultiRangeProofWitness witness = new MultiRangeProofWitness(numbers, randomness);
        RangeProofWitness singleProofWitness = new RangeProofWitness(numbers.get(0), randomness.get(0));
        RangeProof proof = new MultiRangeProofProver().generateProof(parameters, commitments, witness);
        RangeProof singlePRoof = new RangeProofProver().generateProof(parameters, commitments.get(0), singleProofWitness);
        RangeProofVerifier verifier = new RangeProofVerifier();
        verifier.verify(parameters, commitments.get(0), singlePRoof);

        verifier.verify(parameters, commitments.get(0), proof);
        MultiRangeProofVerifier multiRangeProofVerifier = new MultiRangeProofVerifier();
        multiRangeProofVerifier.verify(parameters, commitments, proof);
        multiRangeProofVerifier.verify(parameters, commitments, singlePRoof);


    }

    @Test
    public void testAgainstSingleProof100Times() throws VerificationFailedException {
        MultiRangeProofSystem system = new MultiRangeProofSystem();
        GeneratorParams parameters = system.generateParams(16);
        PeddersenBase base = parameters.getBase();
        for (int i = 0; i < 100; ++i) {
            VectorX<BigInteger> numbers = VectorX.of(ProofUtils.randomNumber(8));
            VectorX<BigInteger> randomness = VectorX.of(ProofUtils.randomNumber());


            GeneratorVector commitments = GeneratorVector.from(numbers.zip(randomness, base::commit));
            MultiRangeProofWitness witness = new MultiRangeProofWitness(numbers, randomness);
            RangeProofWitness singleProofWitness = new RangeProofWitness(numbers.get(0), randomness.get(0));
            RangeProof proof = new MultiRangeProofProver().generateProof(parameters, commitments, witness);
            RangeProof singlePRoof = new RangeProofProver().generateProof(parameters, commitments.get(0), singleProofWitness);
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

        GeneratorParams parameters = system.generateParams(1024);

        VectorX<BigInteger> numbers = VectorX.generate(16, () -> ProofUtils.randomNumber(60)).materialize();

        VectorX<BigInteger> rs = VectorX.generate(16, ProofUtils::randomNumber).materialize();

        GeneratorVector commitments = GeneratorVector.from(numbers.zip(rs, parameters.getBase()::commit));
        MultiRangeProofWitness witness = new MultiRangeProofWitness(numbers, rs);
        RangeProof rangeProof = new MultiRangeProofProver().generateProof(parameters, commitments, witness);
        new MultiRangeProofVerifier().verify(parameters, commitments, rangeProof);

    }


}