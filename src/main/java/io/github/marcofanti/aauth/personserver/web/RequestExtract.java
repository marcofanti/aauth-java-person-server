package io.github.marcofanti.aauth.personserver.web;

import io.github.marcofanti.aauth.personserver.ps.web.HttpSigAuth.SignedRequest;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/** Build a {@link SignedRequest} (method, full URL, lower-cased headers, body) from a servlet request. */
public final class RequestExtract {

    private RequestExtract() {}

    public static SignedRequest signedRequest(HttpServletRequest request, byte[] body) {
        Map<String, String> headers = new LinkedHashMap<>();
        Enumeration<String> names = request.getHeaderNames();
        while (names.hasMoreElements()) {
            String name = names.nextElement();
            headers.put(name.toLowerCase(Locale.ROOT), request.getHeader(name));
        }
        StringBuilder target = new StringBuilder(request.getRequestURL());
        if (request.getQueryString() != null) {
            target.append('?').append(request.getQueryString());
        }
        return new SignedRequest(request.getMethod(), target.toString(), headers, body == null ? new byte[0] : body);
    }
}
