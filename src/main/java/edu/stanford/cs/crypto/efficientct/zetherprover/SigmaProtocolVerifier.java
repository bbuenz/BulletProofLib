package edu.stanford.cs.crypto.efficientct.zetherprover;

import edu.stanford.cs.crypto.efficientct.VerificationFailedException;
import edu.stanford.cs.crypto.efficientct.Verifier;
import edu.stanford.cs.crypto.efficientct.algebra.BN128Point;
import edu.stanford.cs.crypto.efficientct.algebra.GroupElement;
import edu.stanford.cs.crypto.efficientct.linearalgebra.PeddersenBase;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;

import java.math.BigInteger;
import java.util.Optional;

public class SigmaProtocolVerifier<T extends GroupElement<T>> implements Verifier<PeddersenBase<T>, SigmaProtocolStatement<T>, SigmaProof> {
    @Override
    public void verify(PeddersenBase<T> params, SigmaProtocolStatement<T> input, SigmaProof proof, Optional<BigInteger> salt) throws VerificationFailedException {
        T g = params.g;
        BigInteger q = params.getGroup().groupOrder();
        T y = input.getStatement().getY();
        T yBar = input.getStatement().getyBar();
        T CLNew = input.getStatement().getBalanceCommitNewL();
        T CRNew = input.getStatement().getBalanceCommitNewR();
        T C = input.getStatement().getOutL();
        T CBar = input.getStatement().getInL();
        T D = input.getStatement().getInOutR();
        BigInteger z = input.getZ();
        BigInteger zSquared = z.pow(2).mod(q);
        BigInteger zCubed = zSquared.multiply(z).mod(q);


        BigInteger c = proof.getC();
        BigInteger minusC = c.negate().mod(q);
        BigInteger sX = proof.getsX();
        BigInteger sR = proof.getsR();
        T Ay = g.multiply(sX).add(y.multiply(minusC));

        T AD = g.multiply(sR).add(D.multiply(minusC));

        T ADiff = y.subtract(yBar).multiply(sR).add(C.subtract(CBar).multiply(minusC));
        //T CCommit=CL.add(C.multiply(zMin1)).multiply(proof.getC()).add(D.multiply(zMin1.negate()).subtract(CR).multiply(sX)).multiply(zSquared);
        T cCommit = C.multiply(c.multiply(zSquared)).subtract(CRNew.multiply(sX.multiply(zCubed))).add(CLNew.multiply(c.multiply(zCubed))).subtract(D.multiply(sX.multiply(zSquared)));
        T At = g.multiply(input.getT().multiply(c)).add(params.h.multiply(input.getTauX().multiply(c))).subtract(cCommit).subtract(input.gettCommits().multiply(c));
        System.out.printf("Assert.equal(0x%s,As[0].X,\"As[0]\");\n",((BN128Point)Ay).getPoint().normalize().getXCoord());
        System.out.printf("Assert.equal(0x%s,As[1].X,\"As[1]\");\n",((BN128Point)AD).getPoint().normalize().getXCoord());
        System.out.printf("Assert.equal(0x%s,As[2].X,\"As[2]\");\n",((BN128Point)ADiff).getPoint().normalize().getXCoord());
        System.out.printf("Assert.equal(0x%s,As[3].X,\"As[3]\");\n",((BN128Point)At).getPoint().normalize().getXCoord());
        System.out.printf("Assert.equal(0x%s,cCommit.X,\"ccommit\");\n",((BN128Point)cCommit).getPoint().normalize().getXCoord());
        System.out.printf("Assert.equal(0x%s,tCommits.X,\"tCommits\");\n",((BN128Point)input.gettCommits()).getPoint().normalize().getXCoord());
        System.out.println(input.getT().mod(params.getGroup().groupOrder()).toString(16));
        BigInteger challenge;
        if (salt.isPresent()) {
            challenge = ProofUtils.computeChallenge(q, salt.get(), Ay, AD, ADiff, At);
        } else {
            challenge = ProofUtils.computeChallenge(q, Ay, AD, ADiff, At);

        }
        equal(c, challenge, "Challenge equal Sigma Protocol");
    }

}
