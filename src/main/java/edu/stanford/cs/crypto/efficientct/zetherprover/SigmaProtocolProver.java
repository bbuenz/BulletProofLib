package edu.stanford.cs.crypto.efficientct.zetherprover;

import edu.stanford.cs.crypto.efficientct.Proof;
import edu.stanford.cs.crypto.efficientct.Prover;
import edu.stanford.cs.crypto.efficientct.algebra.Group;
import edu.stanford.cs.crypto.efficientct.algebra.GroupElement;
import edu.stanford.cs.crypto.efficientct.linearalgebra.PeddersenBase;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;

import java.math.BigInteger;
import java.util.Optional;

public class SigmaProtocolProver<T extends GroupElement<T>> implements Prover<PeddersenBase<T>, SigmaProtocolStatement<T>, SigmaProtocolWitness, SigmaProof> {

    @Override
    public SigmaProof generateProof(PeddersenBase<T> base, SigmaProtocolStatement<T> input, SigmaProtocolWitness witness, Optional<BigInteger> salt) {
        Group<T> group = base.getGroup();
        BigInteger q = group.groupOrder();
        T g = base.g;

        T y = input.getStatement().getY();
        T yBar = input.getStatement().getyBar();
        T CRNew = input.getStatement().getBalanceCommitNewR();
        T D = input.getStatement().getInOutR();
        BigInteger z = input.getZ();
        BigInteger zSquared = z.pow(2).mod(q);
        BigInteger zCubed = zSquared.multiply(z).mod(q);

        BigInteger kR = ProofUtils.randomNumber();
        BigInteger kX = ProofUtils.randomNumber();
        T Ay = g.multiply(kX);
        T AD = g.multiply(kR);
        T ADiff = y.subtract(yBar).multiply(kR);
        T At = D.multiply(zSquared).add(CRNew.multiply(zCubed)).multiply(kX);

        BigInteger challenge;
        if (salt.isPresent()) {
            challenge = ProofUtils.computeChallenge(q, salt.get(), Ay, AD, ADiff, At);
        } else {
            challenge = ProofUtils.computeChallenge(q, Ay, AD, ADiff, At);

        }
        BigInteger sX = kX.add(challenge.multiply(witness.getX())).mod(q);
        BigInteger sR = kR.add(challenge.multiply(witness.getR())).mod(q);

        return new SigmaProof(challenge, sX, sR);
    }
}
