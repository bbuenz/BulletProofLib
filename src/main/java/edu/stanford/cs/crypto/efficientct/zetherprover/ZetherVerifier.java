package edu.stanford.cs.crypto.efficientct.zetherprover;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.GeneratorParams;
import edu.stanford.cs.crypto.efficientct.VerificationFailedException;
import edu.stanford.cs.crypto.efficientct.Verifier;
import edu.stanford.cs.crypto.efficientct.algebra.GroupElement;
import edu.stanford.cs.crypto.efficientct.innerproduct.EfficientInnerProductVerifier;
import edu.stanford.cs.crypto.efficientct.innerproduct.ExtendedInnerProductProof;
import edu.stanford.cs.crypto.efficientct.innerproduct.ExtendedInnerProductVerifier;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.PeddersenBase;
import edu.stanford.cs.crypto.efficientct.linearalgebra.VectorBase;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * Created by buenz on 7/1/17.
 */
public class ZetherVerifier<T extends GroupElement<T>> implements Verifier<GeneratorParams<T>, ZetherStatement<T>, ZetherProof<T>> {
    private final SigmaProtocolVerifier<T> sigmaVerifier = new SigmaProtocolVerifier<>();
    private final ExtendedInnerProductVerifier<T> ipVerifier = new ExtendedInnerProductVerifier<>();


    @Override
    public void verify(GeneratorParams<T> params, ZetherStatement<T> zetherStatement, ZetherProof<T> proof, Optional<BigInteger> salt) throws VerificationFailedException {
        VectorBase<T> vectorBase = params.getVectorBase();
        PeddersenBase<T> base = params.getBase();
        int n = vectorBase.getGs().size();
        T a = proof.getaI();
        T s = proof.getS();

        BigInteger q = params.getGroup().groupOrder();
        BigInteger y;
        BigInteger statementHash=ProofUtils.computeChallenge(q, zetherStatement.getY(), zetherStatement.getyBar(), zetherStatement.getBalanceCommitNewL(), zetherStatement.getBalanceCommitNewR(), zetherStatement.getInL(), zetherStatement.getOutL(), zetherStatement.getInOutR());
        if (salt.isPresent()) {

            y = ProofUtils.computeChallenge(q,new BigInteger[]{ salt.get(),statementHash} , a, s);
        } else {
            y = ProofUtils.computeChallenge(q,statementHash, a, s);

        }
        FieldVector ys = FieldVector.from(VectorX.iterate(n, BigInteger.ONE, y::multiply), q);

        BigInteger z = ProofUtils.challengeFromints(q, y);

        FieldVector zs = FieldVector.from(VectorX.iterate(2, z.pow(2), z::multiply).map(bi -> bi.mod(q)), q);

        VectorX<BigInteger> twoVector = VectorX.iterate(n / 2, BigInteger.ONE, bi -> bi.shiftLeft(1));
        FieldVector twos = FieldVector.from(twoVector, q);
        FieldVector twoTimesZSquared = FieldVector.from(zs.getVector().flatMap(twos::times), q);
        System.out.println(twoTimesZSquared.size());
        //zs=z^2,z^3 (z-z^2)-(z^2+z^3)*2^(n-2)
        BigInteger zSum = zs.sum().multiply(z).mod(q);

        BigInteger k = ys.sum().multiply(z.subtract(zs.get(0))).subtract(zSum.multiply(twos.sum())).mod(q);


        GeneratorVector<T> tCommits = proof.gettCommits();
        BigInteger x = ProofUtils.computeChallenge(q, z, tCommits);

        T tEval = tCommits.commit(Arrays.asList(x, x.pow(2)));
        BigInteger t = proof.getT();
        BigInteger mu = proof.getMu();
        BigInteger tauX = proof.getTauX();
        SigmaProtocolStatement<T> sigmaStatement = new SigmaProtocolStatement<>(zetherStatement, tEval, t.subtract(k), tauX, z);
        SigmaProof sigmaProof = proof.getSigmaProof();
        sigmaVerifier.verify(base, sigmaStatement, sigmaProof, x);
        BigInteger uChallenge = ProofUtils.challengeFromints(q, sigmaProof.getC(), t, tauX, mu);
        T u = base.g.multiply(uChallenge);
        GeneratorVector<T> hs = vectorBase.getHs();
        GeneratorVector<T> gs = vectorBase.getGs();
        GeneratorVector<T> hPrimes = hs.haddamard(ys.invert());
        FieldVector hExp = ys.times(z).add(twoTimesZSquared);
        T P = a.add(s.multiply(x)).add(gs.sum().multiply(z.negate())).add(hPrimes.commit(hExp)).subtract(base.h.multiply(mu)).add(u.multiply(t));
        VectorBase<T> primeBase = new VectorBase<>(gs, hPrimes, u);
        BigInteger c = BigInteger.ZERO;
        ExtendedInnerProductProof<T> productProof = proof.getProductProof();
        for (int i = 0; i < 4; ++i) {
            c = c.add(productProof.getAs().get(i).multiply(productProof.getBs().get(i)).mod(q));
        }
        c = c.mod(q);
        System.out.println("cc " +uChallenge.multiply(c.subtract(proof.getT())).mod(q));

        ipVerifier.verify(primeBase, P, productProof, uChallenge);

    }
}
