package edu.stanford.cs.crypto.efficientct.zether;

import edu.stanford.cs.crypto.efficientct.GeneratorParams;
import edu.stanford.cs.crypto.efficientct.VerificationFailedException;
import edu.stanford.cs.crypto.efficientct.algebra.*;
import edu.stanford.cs.crypto.efficientct.innerproduct.ExtendedInnerProductProof;
import edu.stanford.cs.crypto.efficientct.linearalgebra.PeddersenBase;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;
import edu.stanford.cs.crypto.efficientct.zetherprover.*;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Random;
import java.util.stream.Collector;
import java.util.stream.Collectors;
import java.util.stream.Stream;


/**
 * Created by buenz on 7/1/17.
 */
public class ZetherProverTest<T extends GroupElement<T>> {

    private ZetherProver<BN128Point> prover = new ZetherProver<>();
    private ZetherVerifier<BN128Point> verifier = new ZetherVerifier<>();
    private static final BN128Group group = new BN128Group();
    private GeneratorParams<BN128Point> params = GeneratorParams.generateParams(64, group);

    @BeforeEach
    public void setup() {
        Random rng = new Random(14);
        ProofUtils.setRNG(rng);
    }

    @Test
    public void testCompletness() throws VerificationFailedException {
        PeddersenBase<BN128Point> base = params.getBase();

        BigInteger x = ProofUtils.randomNumber();
        BigInteger r = ProofUtils.randomNumber();
        BigInteger b = BigInteger.valueOf(14);
        BigInteger bStar = BigInteger.valueOf(12342);
        BN128Point g = base.g;
        BN128Point y = g.multiply(x);
        BigInteger rOld = ProofUtils.randomNumber();
        BN128Point CL = g.multiply(b.add(bStar)).add(y.multiply(rOld));

        BN128Point CR = g.multiply(rOld);
        BN128Point C = g.multiply(b).add(y.multiply(r));
        BN128Point D = g.multiply(r);
        BN128Point yBar = group.mapInto(ProofUtils.hash("yBar"));
        BN128Point CHat = g.multiply(b).add(yBar.multiply(r));

        BN128Point newBalanceCommit = CL.subtract(C);
        BN128Point newRandomness = CR.subtract(D);
        ZetherStatement<BN128Point> zetherStatement = new ZetherStatement<>(newBalanceCommit, newRandomness, C, CHat, D, y, yBar);
        ZetherWitness witness = new ZetherWitness(x, r, b, bStar);
        System.out.println("Y "+y);
        System.out.println(g.multiply(BigInteger.valueOf(10)));
        ZetherProof<BN128Point> proof = prover.generateProof(params, zetherStatement, witness);
        verifier.verify(params, zetherStatement, proof);
        System.out.println(String.format("uint[14] commits=[%s,%s,%s,%s,%s,%s,%s];", y, yBar, newBalanceCommit, newRandomness, CHat, C, D));
        System.out.println(String.format("uint[11] proof=[%s,%s,%s,%s,%s,%s,%s];", proof.getaI(), proof.getS(), proof.gettCommits().get(0), proof.gettCommits().get(1), proof.getTauX(), proof.getT(), proof.getMu()));
        SigmaProof sigmaProof = proof.getSigmaProof();
        System.out.println(String.format("uint[3] sigmaProof=[%s,%s,%s];", sigmaProof.getsX(), sigmaProof.getsR(), sigmaProof.getC()));
        ExtendedInnerProductProof<BN128Point> ip = proof.getProductProof();
        Stream<String> lsStream = Stream.concat(ip.getL().stream(), ip.getR().stream()).map(BN128Point::toString);
        Stream<String> abStream = Stream.concat(ip.getAs().stream(), ip.getBs().stream()).map(bi->bi.toString(16)).map("0x"::concat);
        System.out.println(String.format("uint[24] ipproof=[%s];", Stream.concat(lsStream, abStream).collect(Collectors.joining(","))));

    }

    @Test
    public void testSoundness() {
        PeddersenBase<BN128Point> base = params.getBase();
        BigInteger x = ProofUtils.randomNumber();
        BigInteger r = ProofUtils.randomNumber();
        BigInteger b = BigInteger.valueOf(4294967296L);
        BigInteger bStar = BigInteger.valueOf(12342);

        BN128Point g = base.g;
        BN128Point y = g.multiply(x);
        BigInteger rOld = ProofUtils.randomNumber();
        BN128Point CL = g.multiply(b.add(bStar)).add(y.multiply(rOld));

        BN128Point CR = g.multiply(rOld);
        BN128Point C = g.multiply(b).add(y.multiply(r));
        BN128Point D = g.multiply(r);
        BN128Point yBar = group.mapInto(ProofUtils.hash("yBar"));
        BN128Point CHat = g.multiply(b).add(yBar.multiply(r));


        ZetherStatement<BN128Point> zetherStatement = new ZetherStatement<>(CL.subtract(C), CR.subtract(D), C, CHat, D, y, yBar);
        ZetherWitness witness = new ZetherWitness(x, r, b, bStar);


        ZetherProof<BN128Point> proof = prover.generateProof(params, zetherStatement, witness);
        Assertions.assertThrows(VerificationFailedException.class, () -> verifier.verify(params, zetherStatement, proof));

    }


}