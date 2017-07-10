package edu.stanford.cs.crypto.efficientct;

/**
 * Created by buenz on 6/29/17.
 */
public class VerificationFailedException extends Exception {
    public VerificationFailedException() {
    }

    public VerificationFailedException(String message) {
        super(message);
    }

    public VerificationFailedException(String message, Throwable cause) {
        super(message, cause);
    }

    public VerificationFailedException(Throwable cause) {
        super(cause);
    }

    public VerificationFailedException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
