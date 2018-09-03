package edu.stanford.cs.crypto.efficientct.circuitproof;

import com.google.gson.*;
import edu.stanford.cs.crypto.efficientct.VerificationFailedException;
import edu.stanford.cs.crypto.efficientct.circuit.*;
import edu.stanford.cs.crypto.efficientct.algebra.BouncyCastleECPoint;
import edu.stanford.cs.crypto.efficientct.algebra.Group;
import edu.stanford.cs.crypto.efficientct.algebra.Secp256k1;
import edu.stanford.cs.crypto.efficientct.util.CustomGson;
import edu.stanford.cs.crypto.efficientct.GeneratorParams;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;
import edu.stanford.cs.crypto.efficientct.commitments.PeddersenCommitment;
import org.junit.Test;

import java.math.BigInteger;

public class CircuitParserTest {
    private Group<BouncyCastleECPoint> group = new Secp256k1();

    @Test
    public void testGsonComponents() {
        Gson gson = CustomGson.getGson();
        GeneratorParams<BouncyCastleECPoint> params = GeneratorParams.generateParams(8,group);

        PeddersenCommitment<BouncyCastleECPoint> commitment = new PeddersenCommitment<>(params.getBase(), BigInteger.valueOf(253), ProofUtils.randomNumber());
        ArithmeticCircuit circuit = RangeProofCircuit.createCircuit(8, commitment.getCommitment(),group);

        String json = (gson.toJson(circuit.getCommitments()));

        System.out.println(json);
    }

    @Test
    public void testCircuitParser() throws VerificationFailedException {

        CircuitParser parser = new CircuitParser();
        GeneratorParams<BouncyCastleECPoint> params = GeneratorParams.generateParams(8,group);

        PeddersenCommitment<BouncyCastleECPoint> commitment = new PeddersenCommitment<>(params.getBase(), BigInteger.valueOf(253), ProofUtils.randomNumber());
        ArithmeticCircuit<BouncyCastleECPoint> circuit = RangeProofCircuit.createCircuit(8, commitment.getCommitment(),group);
        String json = parser.parseCircuit(circuit);
        ArithmeticCircuit<BouncyCastleECPoint> circuit2 = parser.readCircuit(json);
        CircuitProver<BouncyCastleECPoint> prover = new CircuitProver<>();

        CircuitWitness<BouncyCastleECPoint> witness = RangeProofCircuit.fromRangeProofWittness(commitment, 8,group);
        CircuitProof<BouncyCastleECPoint> proof = prover.generateProof(params,circuit2,witness);
        CircuitVerifier<BouncyCastleECPoint> verifier = new CircuitVerifier<>();
        verifier.verify(params, circuit2, proof);
    }
}
