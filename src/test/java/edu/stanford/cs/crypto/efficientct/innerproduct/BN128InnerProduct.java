package edu.stanford.cs.crypto.efficientct.innerproduct;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.GeneratorParams;
import edu.stanford.cs.crypto.efficientct.VerificationFailedException;
import edu.stanford.cs.crypto.efficientct.algebra.BN128Group;
import edu.stanford.cs.crypto.efficientct.algebra.BN128Point;
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
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Test;

import java.math.BigInteger;
import java.util.BitSet;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class BN128InnerProduct {

    @Test
    public void createInnerProductProof() throws VerificationFailedException {
        InnerProductProofSystem<BN128Point> system = new InnerProductProofSystem<>();
        BN128Group group = new BN128Group();
        VectorBase<BN128Point> base = system.generatePublicParams(32, group);
        base.getGs().getVector().map(BN128Point::getPoint).map(ECPoint::normalize).map(p -> "=[0x" + p.getXCoord() + " , 0x" + p.getYCoord() + "];").zipWithIndex().map(t -> "garr[" + t.v2 + "]" + t.v1).printOut();
        base.getHs().getVector().map(BN128Point::getPoint).map(ECPoint::normalize).map(p -> "=[0x" + p.getXCoord() + " , 0x" + p.getYCoord() + "];").zipWithIndex().map(t -> "harr[" + t.v2 + "]" + t.v1).printOut();
        System.out.println(base.getH());
        System.out.println(Stream.concat(base.getGs().stream(),base.getHs().stream()).map(BN128Point::getPoint).map(ECPoint::normalize).map(ECPoint::getXCoord).map(Object::toString).map("0x"::concat).collect(Collectors.joining(", ")));
        System.out.println(Stream.concat(base.getGs().stream(),base.getHs().stream()).map(BN128Point::getPoint).map(ECPoint::normalize).map(ECPoint::getYCoord).map(Object::toString).map("0x"::concat).collect(Collectors.joining(", ")));

        FieldVector as = FieldVector.pow(BigInteger.valueOf(2), 32, group.groupOrder());
        //  System.out.println(as);
        FieldVector bs = FieldVector.pow(BigInteger.ONE, 32, group.groupOrder());
        //  System.out.println(bs);
        InnerProductWitness witness = new InnerProductWitness(as, bs);
        BN128Point point = base.commit(as, bs, as.innerPoduct(bs));
        ECPoint pe = point.getPoint().normalize();
        System.out.println("c=EC.Point(0x" + pe.getXCoord() + " , 0x" + pe.getYCoord() + ")");
        InnerProductProof<BN128Point> productProof = system.getProver().generateProof(base, point, witness);
        System.out.println(productProof.getL().size());
        String lstring = productProof.getL().stream().map(BN128Point::getPoint).map(ECPoint::normalize).map(p -> "=[0x" + p.getXCoord() + " , 0x" + p.getYCoord() + "];").collect(Collectors.joining("\n"));
        String rstring = productProof.getR().stream().map(BN128Point::getPoint).map(ECPoint::normalize).map(p -> "=[0x" + p.getXCoord() + " , 0x" + p.getYCoord() + "];").collect(Collectors.joining("\n"));

        System.out.println(lstring);
        System.out.println("RS");
        System.out.println(rstring);
        System.out.println(productProof.getA().toString(16));
        BigInteger q = BN128Group.ORDER;
        System.out.println("B:" +productProof.getB().mod(q).toString(16));

        System.out.println("B:" +productProof.getB().multiply(productProof.getA().modInverse(q)).mod(q).toString(16));
        System.out.println(pe.normalize());
        System.out.println(pe.normalize().negate());
        InnerProductVerifier<BN128Point> tInnerProductVerifier = new InnerProductVerifier<>();
        tInnerProductVerifier.verify(base, point, productProof);
        Keccak.Digest256 digest256 = new Keccak.Digest256();
        BN128Point l4 = productProof.getL().get(4);
        BN128Point r4 = productProof.getR().get(4);

        digest256.update(l4.getPoint().normalize().getXCoord().toBigInteger().toByteArray());
        digest256.update(l4.getPoint().normalize().getYCoord().toBigInteger().toByteArray());
        digest256.update(r4.getPoint().normalize().getXCoord().toBigInteger().toByteArray());
        digest256.update(r4.getPoint().normalize().getYCoord().toBigInteger().toByteArray());
        System.out.println(l4.getPoint().normalize());
        System.out.println(r4.getPoint().normalize());
        List<BigInteger> challenges = VectorX.fromIterable(productProof.getL()).zip(productProof.getR()).map(t -> ProofUtils.computeChallenge(q, t.v1, t.v2)).toList();
        challenges.stream().map(bi -> bi.pow(2).mod(q)).forEach(System.out::println);
        int n = 32;
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
        for (int i = 0; i < 32; ++i) {
            System.out.println(i + " " + otherExponents[i].mod(q));
        }
        System.out.println(challenges.get(0).multiply(challenges.stream().skip(1).reduce(BigInteger.ONE, BigInteger::multiply).modInverse(q)).mod(q));
        System.out.println(otherExponents[0].multiply(challenges.get(0).multiply(challenges.get(0))).mod(q));
        System.out.println(challenges.stream().reduce(BigInteger.ONE, BigInteger::multiply).modInverse(q));
        BigInteger chal5 = new BigInteger("9000376896660140145009348915025745626352417549140741295195137676953295299173");
        System.out.println(challenges.get(0).pow(2).mod(q));
        System.out.println(challenges.get(0).multiply(challenges.get(0)).mod(q));

        BigInteger exp0 = new BigInteger("18814982702849560844990085635879685722136724614664326524377045111907579183542");
        System.out.println(chal5.multiply(exp0).mod(q));
        EfficientInnerProductVerifier<BN128Point> efficientInnerProductVerifier = new EfficientInnerProductVerifier<>();
        efficientInnerProductVerifier.verify(base, point, productProof);
        System.out.println(base.getH());
        System.out.println(point);
    }
    @Test
    public void testRangeProof() throws VerificationFailedException {
        BigInteger number = BigInteger.valueOf(5);
        BigInteger randomness = BigInteger.valueOf(14);
        BN128Group group=new BN128Group();
        GeneratorParams<BN128Point> parameters = GeneratorParams.generateParams(32,group);
        BN128Point v = parameters.getBase().commit(number, randomness);
        PeddersenCommitment<BN128Point> witness = new PeddersenCommitment<>(parameters.getBase(),number, randomness);
        RangeProof<BN128Point> proof = new FixedRandomnessRangeProofProver<BN128Point>(13).generateProof(parameters, v, witness);
        BigInteger a = proof.getProductProof().getA();
        BigInteger aInvB = proof.getProductProof().getB().multiply(a.modInverse(BN128Group.ORDER)).mod(BN128Group.ORDER);
        System.out.println(String.format("proof=[%s,%s,%s,%s,%s,%s,%s,%s,%s,%s]",v,proof.getaI(),proof.getS(),proof.gettCommits().get(0),proof.gettCommits().get(1),proof.getTauX(),proof.getMu(),proof.getT(), a, aInvB));
        System.out.println("ls="+proof.getProductProof().getL().stream().map(BN128Point::toString).map(s->String.format("[%s]",s)).collect(Collectors.toList()));
        System.out.println("rs="+proof.getProductProof().getR().stream().map(BN128Point::toString).map(s->String.format("[%s]",s)).collect(Collectors.toList()));
        RangeProofVerifier<BN128Point> verifier = new RangeProofVerifier<>();
        verifier.verify(parameters, v, proof);
        System.out.println(new BigInteger("bcdfd5a1f352aaacee9477514f5ad587ea88a261cdab9f7359fd680935d76f6",16));
        System.out.println(new BigInteger("1e9d8f75c5d242978e759a6d5c3ac544898bff41909dfc2d353d7cd1ea0f1e12",16));
        EfficientRangeProofVerifier<BN128Point> efficientRangeProofVerifier=new EfficientRangeProofVerifier<>();
        efficientRangeProofVerifier.verify(parameters,v,proof);
    }
    @Test
    public void generateExponentiationCode(){
        InnerProductProofSystem<BN128Point> system = new InnerProductProofSystem<>();
        BN128Group group = new BN128Group();
        VectorBase<BN128Point> base = system.generatePublicParams(32, group);
        for(int i=0;i<32;++i){
            BN128Point gi = base.getGs().get(i);
            String line=String.format("temp=Curve.g1mul(%s,gExps[%d]);", gi.toString(),i);
            System.out.println(line);
            System.out.println(String.format("commitment=Curve.g1add(temp,commitment);"));
        }
        for(int i=0;i<32;++i){
            BN128Point hi = base.getHs().get(i);
            String line=String.format("temp=Curve.g1mul(%s,hExps[%d]);", hi.toString(),i);
            System.out.println(line);
            System.out.println(String.format("commitment=Curve.g1add(temp,commitment);"));
        }
    }
}
