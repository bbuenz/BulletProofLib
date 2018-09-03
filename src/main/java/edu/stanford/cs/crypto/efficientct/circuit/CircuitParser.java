package edu.stanford.cs.crypto.efficientct.circuit;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.algebra.BouncyCastleECPoint;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;
import edu.stanford.cs.crypto.efficientct.util.CustomGson;

import java.io.IOException;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;

public class CircuitParser {

    private final Gson gson = CustomGson.getGson();
    ;


    public void writeCricuit(Path path, ArithmeticCircuit circuit) throws IOException {
        String json = parseCircuit(circuit);
        Files.write(path, json.getBytes());
    }

    public String parseCircuit(ArithmeticCircuit circuit) {

        String jsonString = gson.toJson(circuit);
        return jsonString;
    }

    public ArithmeticCircuit<BouncyCastleECPoint> readCircuit(String json) {
        return gson.fromJson(json, new TypeToken<ArithmeticCircuit<BouncyCastleECPoint>>() {
        }.getType());
    }

    public ArithmeticCircuit readCircuit(Path path) throws IOException {
        try (Reader reader = Files.newBufferedReader(path)) {
            return gson.fromJson(reader, ArithmeticCircuit.class);
        }

    }

    private String parseMatrix(VectorX<FieldVector> matrix) {
        return gson.toJson(matrix);
    }
}
