package edu.stanford.cs.crypto;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;
import org.bouncycastle.math.ec.ECPoint;
import org.openjdk.jmh.annotations.*;

import java.math.BigInteger;

/**
 * Created by buenz on 7/9/17.
 */
@State(Scope.Benchmark)
public class OtherBenchmarks {
    BigInteger y = ProofUtils.challengeFromInts(BigInteger.ONE);
    ECPoint g = ECConstants.G;

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    public FieldVector noMod() {
        return FieldVector.from(VectorX.iterate(16, BigInteger.ONE, y::multiply).materialize());

    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    public FieldVector withMod() {
        return FieldVector.from(VectorX.iterate(16, BigInteger.ONE, y::multiply).map(bi -> bi.mod(ECConstants.P)).materialize());

    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    public ECPoint groupExp() {
        return g.multiply(y);
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    public BigInteger square1() {
        return y.pow(2);
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    public BigInteger square2() {
        return y.modPow(BigInteger.valueOf(2), ECConstants.P);
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    public BigInteger squareMod() {
        return y.pow(2).mod(ECConstants.P);
    }

}
