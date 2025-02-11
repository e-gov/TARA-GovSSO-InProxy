package ee.ria.govsso.inproxy.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

import java.util.Objects;

@Getter
public class HydraStyleException extends RuntimeException {

    public static final String INVALID_REQUEST = "invalid_request";

    private final String errorDescription;
    private final HttpStatus statusCode;

    public HydraStyleException(String error, String errorDescription, HttpStatus statusCode, Throwable cause) {
        super(error, cause);
        this.errorDescription = errorDescription;
        this.statusCode = statusCode;
    }

    public HydraStyleException(String error, String errorDescription, HttpStatus statusCode) {
        super(error);
        this.errorDescription = errorDescription;
        this.statusCode = statusCode;
    }

    public HydraStyleException(String error, String errorDescription) {
        super(error);
        this.errorDescription = errorDescription;
        this.statusCode = null;
    }

    public HttpStatus getHttpStatus() {
        return Objects.requireNonNull(statusCode, "Status code not provided");
    }

    public String getError() {
        return getMessage();
    }

}
