package edu.stanford.cs.crypto.efficientct.zetherprover;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.FieldPolynomial;
import edu.stanford.cs.crypto.efficientct.FieldVectorPolynomial;
import edu.stanford.cs.crypto.efficientct.GeneratorParams;
import edu.stanford.cs.crypto.efficientct.Prover;
import edu.stanford.cs.crypto.efficientct.algebra.GroupElement;
import edu.stanford.cs.crypto.efficientct.commitments.PeddersenCommitment;
import edu.stanford.cs.crypto.efficientct.commitments.PolyCommitment;
import edu.stanford.cs.crypto.efficientct.innerproduct.*;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.PeddersenBase;
import edu.stanford.cs.crypto.efficientct.linearalgebra.VectorBase;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;

import java.math.BigInteger;
import java.util.Optional;

/**
 * Created by buenz on 7/2/17.
 */
public class ZetherProver<T extends GroupElement<T>> implements Prover<GeneratorParams<T>, ZetherStatement<T>, ZetherWitness, ZetherProof<T>> {


    @Override
    public ZetherProof<T> generateProof(GeneratorParams<T> parameter, ZetherStatement<T> zetherStatement, ZetherWitness witness, Optional<BigInteger> salt) {
        BigInteger q = parameter.getGroup().groupOrder();

        VectorBase<T> vectorBase = parameter.getVectorBase();
        int n = vectorBase.getGs().size();
        BigInteger number = witness.getbTransfer().add(witness.getbDiff().shiftLeft(n / 2));
        PeddersenBase<T> base = parameter.getBase();
        FieldVector aL = FieldVector.from(VectorX.range(0, n).map(i -> number.testBit(i) ? BigInteger.ONE : BigInteger.ZERO), q);
        FieldVector aR = aL.subtract(VectorX.fill(n, BigInteger.ONE));
        BigInteger alpha = ProofUtils.randomNumber();
        T a = vectorBase.commit(aL, aR, alpha);
        // FieldVector sR = FieldVector.from(VectorX.generate(n, ProofUtils::randomNumber), q);
        // FieldVector sL = FieldVector.from(VectorX.generate(n, ProofUtils::randomNumber), q);
        FieldVector sL = FieldVector.pow(BigInteger.ZERO, n, q);
        FieldVector sR = FieldVector.pow(BigInteger.ZERO, n, q);

        BigInteger rho = ProofUtils.randomNumber();
        T s = vectorBase.commit(sL, sR, rho);
        BigInteger y;
        BigInteger statementHash=ProofUtils.computeChallenge(q, zetherStatement.getY(), zetherStatement.getyBar(), zetherStatement.getBalanceCommitNewL(), zetherStatement.getBalanceCommitNewR(), zetherStatement.getInL(), zetherStatement.getOutL(), zetherStatement.getInOutR());
        if (salt.isPresent()) {

            y = ProofUtils.computeChallenge(q,new BigInteger[]{ salt.get(),statementHash} , a, s);
        } else {
            y = ProofUtils.computeChallenge(q,statementHash, a, s);

        }
        System.out.printf("Assert.equal(chals[0],%s,\"y\");\n", y);
        FieldVector ys = FieldVector.from(VectorX.iterate(n, BigInteger.ONE, y::multiply), q);
        BigInteger z = ProofUtils.challengeFromints(q, y);
        System.out.printf("Assert.equal(chals[1],%s,\"z\");\n", z);

        //z^Q
        FieldVector zs = FieldVector.from(VectorX.iterate(2, z.pow(2), z::multiply).map(bi -> bi.mod(q)), q);
        //2^n
        VectorX<BigInteger> twoVector = VectorX.iterate(n / 2, BigInteger.ONE, bi -> bi.shiftLeft(1));
        FieldVector twos = FieldVector.from(twoVector, q);
        //2^n \cdot z || 2^n \cdot z^2 ...
        FieldVector twoTimesZs = FieldVector.from(zs.getVector().flatMap(twos::times), q);
        //l(X)
        FieldVector l0 = aL.add(z.negate());
        FieldVector l1 = sL;
        FieldVectorPolynomial lPoly = new FieldVectorPolynomial(l0, l1);
        //r(X)
        FieldVector r0 = ys.hadamard(aR.add(z)).add(twoTimesZs);
        FieldVector r1 = sR.hadamard(ys);
        FieldVectorPolynomial rPoly = new FieldVectorPolynomial(r0, r1);

        //t(X)
        FieldPolynomial tPoly = lPoly.innerProduct(rPoly);
        //Commit(t)
        BigInteger[] tPolyCoefficients = tPoly.getCoefficients();
        PolyCommitment<T> polyCommitment = PolyCommitment.from(base, tPolyCoefficients[0], VectorX.of(tPolyCoefficients).skip(1));
        //TODO:Take z into the challenge

        BigInteger x = ProofUtils.computeChallenge(q, z, polyCommitment.getCommitments());
        System.out.printf("Assert.equal(chals[2],%s,\"x\");\n", x);

        PeddersenCommitment<T> evalCommit = polyCommitment.evaluate(x);
        BigInteger t = evalCommit.getX();
        BigInteger mu = alpha.add(rho.multiply(x)).mod(q);

        SigmaProtocolProver<T> protocolProver = new SigmaProtocolProver<>();
        BigInteger zSum = zs.sum().multiply(z).mod(q);
        BigInteger k = ys.sum().multiply(z.subtract(zs.get(0))).subtract(zSum.shiftLeft(n / 2).subtract(zSum)).mod(q);
        System.out.printf("Assert.equal(0x%s,delta,\"delta\");\n",k.toString(16));
        BigInteger tauX = evalCommit.getR();
        SigmaProtocolStatement<T> sigmaStatement = new SigmaProtocolStatement<>(zetherStatement, evalCommit.getCommitment().subtract(base.g.multiply(tPolyCoefficients[0])), t.subtract(k), tauX, z);
        SigmaProtocolWitness sigmaWitness = new SigmaProtocolWitness(witness.getX(), witness.getR());
        SigmaProof sigmaProof = protocolProver.generateProof(base, sigmaStatement, sigmaWitness, x);

        BigInteger uChallenge = ProofUtils.challengeFromints(q, sigmaProof.getC(), t, tauX, mu);
        System.out.printf("uint[4] chals=[%s,%s,%s,%s];\n", y, z, x, uChallenge);
        T u = base.g.multiply(uChallenge);
        GeneratorVector<T> hs = vectorBase.getHs();
        GeneratorVector<T> gs = vectorBase.getGs();
        GeneratorVector<T> hPrimes = hs.haddamard(ys.invert());
        FieldVector l = lPoly.evaluate(x);
        FieldVector r = rPoly.evaluate(x);
        FieldVector hExp = ys.times(z).add(twoTimesZs);
        T P = a.add(s.multiply(x)).add(gs.sum().multiply(z.negate())).add(hPrimes.commit(hExp)).add(u.multiply(t)).subtract(base.h.multiply(mu));
        VectorBase<T> primeBase = new VectorBase<>(gs, hPrimes, u);
        ExtendedInnerProductProver<T> prover = new ExtendedInnerProductProver<>();
        InnerProductWitness innerProductWitness = new InnerProductWitness(l, r);
        ExtendedInnerProductProof<T> ipProof = prover.generateProof(primeBase, P, innerProductWitness, uChallenge);
        GeneratorVector<T> tCommits = new GeneratorVector<>(polyCommitment.getCommitments(), hs.getGroup());
        return new ZetherProof<>(a, s, tCommits, t, tauX, mu, sigmaProof, ipProof);


    }
}
