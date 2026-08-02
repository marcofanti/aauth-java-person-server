package io.github.marcofanti.aauth.personserver.web;

import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Sanitize Markdown-oriented user/agent text before display (protocol §Markdown String).
 *
 * <p>The Python server uses bleach; here disallowed HTML tags are stripped (their text
 * kept) and {@code <script>}/{@code <style>} blocks removed entirely, preserving plain
 * text and common Markdown-adjacent tags unchanged.
 */
public final class Sanitize {

    private static final Set<String> ALLOWED_TAGS = Set.of(
            "a", "abbr", "acronym", "b", "blockquote", "code", "em", "i", "li", "ol", "strong", "ul", "p", "pre");

    private static final Pattern SCRIPT_BLOCK =
            Pattern.compile("<(script|style)\\b[^>]*>.*?</\\1>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    private static final Pattern TAG = Pattern.compile("</?([a-zA-Z][a-zA-Z0-9]*)\\b[^>]*>");

    private Sanitize() {}

    public static String markdown(String text) {
        String out = SCRIPT_BLOCK.matcher(text).replaceAll("");
        Matcher matcher = TAG.matcher(out);
        StringBuilder result = new StringBuilder();
        while (matcher.find()) {
            String tag = matcher.group(1).toLowerCase(Locale.ROOT);
            matcher.appendReplacement(
                    result, ALLOWED_TAGS.contains(tag) ? Matcher.quoteReplacement(matcher.group()) : "");
        }
        matcher.appendTail(result);
        return result.toString();
    }

    public static String markdownOrNull(String text) {
        return text == null ? null : markdown(text);
    }
}
