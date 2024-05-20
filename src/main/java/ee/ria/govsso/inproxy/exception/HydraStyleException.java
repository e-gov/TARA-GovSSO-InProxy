package ee.ria.govsso.inproxy.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class HydraStyleException extends RuntimeException {

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

    public String getError() {
        return getMessage();
    }

}
