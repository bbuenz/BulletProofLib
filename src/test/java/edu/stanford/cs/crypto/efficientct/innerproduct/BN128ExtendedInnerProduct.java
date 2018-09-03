package edu.stanford.cs.crypto.efficientct.innerproduct;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.GeneratorParams;
import edu.stanford.cs.crypto.efficientct.VerificationFailedException;
import edu.stanford.cs.crypto.efficientct.algebra.BN128Group;
import edu.stanford.cs.crypto.efficientct.algebra.BN128Point;
import edu.stanford.cs.crypto.efficientct.commitments.PeddersenCommitment;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.VectorBase;
import edu.stanford.cs.crypto.efficientct.rangeproof.EfficientRangeProofVerifier;
import edu.stanford.cs.crypto.efficientct.rangeproof.FixedRandomnessRangeProofProver;
import edu.stanford.cs.crypto.efficientct.rangeproof.RangeProof;
import edu.stanford.cs.crypto.efficientct.rangeproof.RangeProofVerifier;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Test;

import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class BN128ExtendedInnerProduct {

    @Test
    public void createInnerProductProof() throws VerificationFailedException {
        InnerProductProofSystem<BN128Point> system = new InnerProductProofSystem<>();
        BN128Group group = new BN128Group();
        VectorBase<BN128Point> base = system.generatePublicParams(64, group);

        FieldVector as = FieldVector.pow(BigInteger.valueOf(2), 64, group.groupOrder());
        //  System.out.println(as);
        FieldVector bs = FieldVector.pow(BigInteger.valueOf(3), 64, group.groupOrder());
        //  System.out.println(bs);
        InnerProductWitness witness = new InnerProductWitness(as, bs);
        BigInteger c = as.innerPoduct(bs);
        System.out.println(c);
        BN128Point point = base.commit(as, bs, c);
        ECPoint pe = point.getPoint().normalize();
        System.out.println("Cuve.G1Point memory c=Curve.G1Point(0x" + pe.getXCoord() + " , 0x" + pe.getYCoord() + ");");
        ExtendedInnerProductProver<BN128Point> prover = new ExtendedInnerProductProver<>();
        ExtendedInnerProductProof<BN128Point> productProof = prover.generateProof(base, point, witness, BigInteger.ZERO);

        System.out.println(productProof.getL().size());
        Stream<String> landrStream = Stream.concat(productProof.getL().stream(), productProof.getR().stream()).map(BN128Point::getPoint).map(ECPoint::normalize).flatMap(p -> Stream.of(p.getXCoord(), p.getYCoord())).map(ECFieldElement::toString);
        List<BigInteger> proofAs = productProof.getAs();
        List<BigInteger> proofBs = productProof.getBs();
        Stream<String> aAndbStream = Stream.concat(proofAs.stream(), proofBs.stream()).map(bi -> bi.toString(16));
        String proofString = Stream.concat(landrStream, aAndbStream).map("0x"::concat).collect(Collectors.joining(","));

        System.out.println(String.format("uint[24] memory ipproof=[%s];", proofString));
        BigInteger q = BN128Group.ORDER;
        ExtendedInnerProductVerifier<BN128Point> tInnerProductVerifier = new ExtendedInnerProductVerifier<BN128Point>();
        tInnerProductVerifier.verify(base, point, productProof);

        List<BigInteger> challenges =VectorX.fromIterable(productProof.getL()).zip(productProof.getR()).scanLeft(BigInteger.ZERO,(salt,t) -> ProofUtils.computeChallenge(q, salt,t.v1,t.v2)).drop(1).toList();
        System.out.println(challenges);
        challenges.stream().map(bi -> bi.pow(2).mod(q)).forEach(System.out::println);
        int n = 16;
        BigInteger[] otherExponents = new BigInteger[n];

        otherExponents[0] = challenges.stream().reduce(BigInteger.ONE, (l, r) -> l.multiply(r).mod(q)).modInverse(q);
        BitSet bitSet = new BitSet();
        Collections.reverse(challenges);
        for (int i = 0; i < n / 2; ++i) {
            for (int j = 0; (1 << j) + i < n; ++j) {

                int i1 = i + (1 << j);
                if (bitSet.get(i1)) {

                } else {
                    otherExponents[i1] = otherExponents[i].multiply(challenges.get(j).pow(2)).mod(q);
                    bitSet.set(i1);
                }
            }
        }
        BigInteger challenge0 = challenges.stream().reduce(BigInteger.ONE, BigInteger::multiply).modInverse(q);
        System.out.println("chal 0 " + challenge0);
        System.out.println(as.get(0));
        List<BigInteger> gExps = new LinkedList<>();
        List<BigInteger> hExps = new LinkedList<>();

        for (int i = 0; i < 16; ++i) {
            System.out.println(String.format("Assert.equal(gExponents[%d],%s,\"G exponent %d\");", i * 4, otherExponents[i].mod(q), i * 4));
        }
        for (int i = 0; i < 64; ++i) {
            BigInteger gExp = otherExponents[i / 4].multiply(proofAs.get(i % 4)).mod(q);
            BigInteger hExp = otherExponents[(63 - i) / 4].multiply(proofBs.get(i % 4)).mod(q);
            System.out.println(String.format("Assert.equal(gExps[%d],%s,\"G exponent %d\");", i, gExp, i));
            System.out.println(String.format("Assert.equal(hExps[%d],%s,\"H exponent %d\");", i, hExp, i));
            gExps.add(gExp);
            hExps.add(hExp);
        }
        BigInteger innerPoduct = FieldVector.from(proofAs, q).innerPoduct(proofBs);
        System.out.println(innerPoduct);
        System.out.println(base.commit(gExps, hExps, innerPoduct));
    }

    @Test
    public void generateExponentiationCode() {
        InnerProductProofSystem<BN128Point> system = new InnerProductProofSystem<>();
        BN128Group group = new BN128Group();
        VectorBase<BN128Point> base = system.generatePublicParams(64, group);
        for (int i = 0; i < 64; ++i) {
            BN128Point gi = base.getGs().get(i);
            String line = String.format("temp=Curve.g1mul(%s,gExps[%d]);", gi.toString(), i);
            System.out.println(line);
            System.out.println(String.format("commitment=Curve.g1add(temp,commitment);"));
        }
        for (int i = 0; i < 64; ++i) {
            BN128Point hi = base.getHs().get(i);
            String line = String.format("temp=Curve.g1mul(%s,hExps[%d]);", hi.toString(), i);
            System.out.println(line);
            System.out.println(String.format("commitment=Curve.g1add(temp,commitment);"));
        }
        VectorX<BigInteger> oneThrough64 = VectorX.range(1, 65).map(BigInteger::valueOf);
        System.out.println(base.commit(oneThrough64, oneThrough64, BigInteger.ZERO));
    }
}
