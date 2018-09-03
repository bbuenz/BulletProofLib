package edu.stanford.cs.crypto.efficientct.zether;

import edu.stanford.cs.crypto.efficientct.VerificationFailedException;
import edu.stanford.cs.crypto.efficientct.algebra.BN128Group;
import edu.stanford.cs.crypto.efficientct.algebra.BN128Point;
import edu.stanford.cs.crypto.efficientct.linearalgebra.PeddersenBase;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;
import edu.stanford.cs.crypto.efficientct.zetherprover.*;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Random;

public class SigmaProtocolTest {
    private SigmaProtocolStatement<BN128Point> statement;
    private SigmaProtocolWitness witness;

    SigmaProtocolProver<BN128Point> prover = new SigmaProtocolProver<>();
    SigmaProtocolVerifier<BN128Point> verifier = new SigmaProtocolVerifier<>();
    private static final BN128Group group = new BN128Group();
    private PeddersenBase<BN128Point> base;

    @BeforeEach
    public void setup() {
        ProofUtils.setRNG(new Random(13));
        BigInteger x = ProofUtils.randomNumber();
        BigInteger r = ProofUtils.randomNumber();
        BigInteger b = BigInteger.valueOf(14);
        BigInteger bStar = BigInteger.valueOf(12342);
        BigInteger z = ProofUtils.randomNumber();
        BN128Point g = group.mapInto(ProofUtils.hash("G"));
        BN128Point y = g.multiply(x);
        BigInteger rOld = ProofUtils.randomNumber();
        BN128Point CL = g.multiply(b.add(bStar)).add(y.multiply(rOld));
        System.out.println(CL);
        System.out.println(g.multiply(b.add(bStar)).add(g.multiply(x.multiply(rOld))));

        BN128Point CR = g.multiply(rOld);
        BN128Point C = g.multiply(b).add(y.multiply(r));
        BN128Point D = g.multiply(r);
        BN128Point yBar = group.mapInto(ProofUtils.hash("yBar"));
        BN128Point CHat = g.multiply(b).add(yBar.multiply(r));
        BigInteger t = ProofUtils.randomNumber();
        BigInteger tauX = ProofUtils.randomNumber();
        BN128Point h = group.mapInto(ProofUtils.hash("V"));
        BigInteger zSquared = z.pow(2).mod(group.groupOrder());
        BigInteger zCubed = zSquared.multiply(z).mod(group.groupOrder());

        BN128Point tCommitment = g.multiply(t.subtract(b.multiply(zSquared)).subtract(bStar.multiply(zCubed))).add(h.multiply(tauX));


        BN128Point CLNew = CL.subtract(C);
        BN128Point CRNew = CR.subtract(D);
        ZetherStatement<BN128Point> zetherStatement = new ZetherStatement<>(CLNew, CRNew, C, CHat, D, y, yBar);
        statement = new SigmaProtocolStatement<>(zetherStatement, tCommitment, t, tauX, z);
        witness = new SigmaProtocolWitness(x, r);
        base = new PeddersenBase<>(g, h, group);
        // statement= (y,yBar,CL,CR,C,CBar,D,TCommits,t,zSquared,zCubed)
        //proof= (sX,sR,sB,sBStar,sMu,c)
        System.out.println(String.format("uint[19] memory statement=[%s,%s,%s,%s,%s,%s,%s,%s,0x%s,0x%s,0x%s];", y, yBar, CLNew, CRNew, C, CHat, D, tCommitment, t.toString(16), tauX.toString(16), z.toString(16)));
    }

    @Test
    public void testCompleteness() throws VerificationFailedException {

        SigmaProof proof = prover.generateProof(base, statement, witness);
        System.out.println(String.format("uint[3] memory proof=[%s];", proof.toStringArray()));
        verifier.verify(base, statement, proof);
    }

    @Test
    public void testSoundness() {
        SigmaProtocolStatement<BN128Point> wrongStatement=new SigmaProtocolStatement<>(statement.getStatement(),statement.gettCommits(),statement.getT().add(statement.getZ().pow(2)),statement.getTauX(),statement.getZ());
        SigmaProof proof = prover.generateProof(base, wrongStatement, witness);
        Assertions.assertThrows(VerificationFailedException.class, () -> verifier.verify(base, wrongStatement, proof));
    }

}
