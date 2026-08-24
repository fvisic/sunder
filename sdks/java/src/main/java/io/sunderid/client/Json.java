package io.sunderid.client;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal hand-rolled JSON support - deliberately no third-party dependency.
 *
 * <p>The Sunder v1 payloads are flat: objects with string values, string
 * arrays, and one nested string map ({@code "attributes"}). The writer
 * handles exactly what the client sends (strings, iterables, maps, numbers,
 * booleans, null); the parser is a small, tolerant reader for full JSON so
 * unexpected extra fields of any type are skipped correctly.
 */
final class Json {

    private Json() {
    }

    // -- writing ---------------------------------------------------------------

    /** Serializes maps, iterables, strings, numbers, booleans and null. */
    static String write(Object value) {
        StringBuilder sb = new StringBuilder();
        writeValue(sb, value);
        return sb.toString();
    }

    private static void writeValue(StringBuilder sb, Object value) {
        if (value == null) {
            sb.append("null");
        } else if (value instanceof String s) {
            writeString(sb, s);
        } else if (value instanceof Boolean || value instanceof Integer
                || value instanceof Long || value instanceof Short
                || value instanceof Byte) {
            sb.append(value);
        } else if (value instanceof Number n) {
            double d = n.doubleValue();
            if (Double.isNaN(d) || Double.isInfinite(d)) {
                throw new IllegalArgumentException("cannot serialize non-finite number: " + n);
            }
            sb.append(n);
        } else if (value instanceof Map<?, ?> map) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : map.entrySet()) {
                if (!(e.getKey() instanceof String key)) {
                    throw new IllegalArgumentException("JSON object keys must be strings");
                }
                if (!first) {
                    sb.append(',');
                }
                first = false;
                writeString(sb, key);
                sb.append(':');
                writeValue(sb, e.getValue());
            }
            sb.append('}');
        } else if (value instanceof Iterable<?> it) {
            sb.append('[');
            boolean first = true;
            for (Object item : it) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                writeValue(sb, item);
            }
            sb.append(']');
        } else if (value instanceof Object[] arr) {
            sb.append('[');
            for (int i = 0; i < arr.length; i++) {
                if (i > 0) {
                    sb.append(',');
                }
                writeValue(sb, arr[i]);
            }
            sb.append(']');
        } else {
            throw new IllegalArgumentException(
                    "cannot serialize value of type " + value.getClass().getName());
        }
    }

    private static void writeString(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
    }

    // -- parsing ---------------------------------------------------------------

    /**
     * Parses a JSON object into a map. Throws {@link JsonException} when the
     * text is not valid JSON or the top-level value is not an object.
     */
    static Map<String, Object> parseObject(String text) {
        Object value = parse(text);
        if (!(value instanceof Map)) {
            throw new JsonException("expected a JSON object");
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> map = (Map<String, Object>) value;
        return map;
    }

    /** Parses any JSON value: Map, List, String, Long/Double, Boolean or null. */
    static Object parse(String text) {
        Parser p = new Parser(text);
        Object value = p.readValue();
        p.skipWhitespace();
        if (!p.atEnd()) {
            throw new JsonException("trailing characters after JSON value");
        }
        return value;
    }

    /** Signals malformed JSON; internal - callers translate it to SunderException. */
    static final class JsonException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        JsonException(String message) {
            super(message);
        }
    }

    private static final class Parser {
        private final String text;
        private int pos;

        Parser(String text) {
            this.text = text;
        }

        boolean atEnd() {
            return pos >= text.length();
        }

        void skipWhitespace() {
            while (pos < text.length()) {
                char c = text.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    pos++;
                } else {
                    break;
                }
            }
        }

        private char peek() {
            if (atEnd()) {
                throw new JsonException("unexpected end of input");
            }
            return text.charAt(pos);
        }

        private void expect(char c) {
            if (atEnd() || text.charAt(pos) != c) {
                throw new JsonException("expected '" + c + "' at position " + pos);
            }
            pos++;
        }

        Object readValue() {
            skipWhitespace();
            char c = peek();
            return switch (c) {
                case '{' -> readObject();
                case '[' -> readArray();
                case '"' -> readString();
                case 't' -> readLiteral("true", Boolean.TRUE);
                case 'f' -> readLiteral("false", Boolean.FALSE);
                case 'n' -> readLiteral("null", null);
                default -> readNumber();
            };
        }

        private Map<String, Object> readObject() {
            expect('{');
            Map<String, Object> map = new LinkedHashMap<>();
            skipWhitespace();
            if (peek() == '}') {
                pos++;
                return map;
            }
            while (true) {
                skipWhitespace();
                String key = readString();
                skipWhitespace();
                expect(':');
                map.put(key, readValue());
                skipWhitespace();
                char c = peek();
                if (c == ',') {
                    pos++;
                } else if (c == '}') {
                    pos++;
                    return map;
                } else {
                    throw new JsonException("expected ',' or '}' at position " + pos);
                }
            }
        }

        private List<Object> readArray() {
            expect('[');
            List<Object> list = new ArrayList<>();
            skipWhitespace();
            if (peek() == ']') {
                pos++;
                return list;
            }
            while (true) {
                list.add(readValue());
                skipWhitespace();
                char c = peek();
                if (c == ',') {
                    pos++;
                } else if (c == ']') {
                    pos++;
                    return list;
                } else {
                    throw new JsonException("expected ',' or ']' at position " + pos);
                }
            }
        }

        private String readString() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (true) {
                if (atEnd()) {
                    throw new JsonException("unterminated string");
                }
                char c = text.charAt(pos++);
                if (c == '"') {
                    return sb.toString();
                }
                if (c == '\\') {
                    if (atEnd()) {
                        throw new JsonException("unterminated escape");
                    }
                    char e = text.charAt(pos++);
                    switch (e) {
                        case '"' -> sb.append('"');
                        case '\\' -> sb.append('\\');
                        case '/' -> sb.append('/');
                        case 'b' -> sb.append('\b');
                        case 'f' -> sb.append('\f');
                        case 'n' -> sb.append('\n');
                        case 'r' -> sb.append('\r');
                        case 't' -> sb.append('\t');
                        case 'u' -> {
                            if (pos + 4 > text.length()) {
                                throw new JsonException("truncated \\u escape");
                            }
                            String hex = text.substring(pos, pos + 4);
                            // Integer.parseInt accepts signs; JSON requires
                            // exactly four hex digits.
                            for (int i = 0; i < 4; i++) {
                                if (Character.digit(hex.charAt(i), 16) < 0) {
                                    throw new JsonException("invalid \\u escape: " + hex);
                                }
                            }
                            sb.append((char) Integer.parseInt(hex, 16));
                            pos += 4;
                        }
                        default -> throw new JsonException("invalid escape: \\" + e);
                    }
                } else {
                    sb.append(c);
                }
            }
        }

        private Object readLiteral(String literal, Object value) {
            if (!text.startsWith(literal, pos)) {
                throw new JsonException("invalid literal at position " + pos);
            }
            pos += literal.length();
            return value;
        }

        private Object readNumber() {
            int start = pos;
            // JSON numbers start with '-' or a digit; a leading '+' would
            // otherwise slip through Double.parseDouble.
            if (!atEnd() && text.charAt(pos) != '-' && Character.digit(text.charAt(pos), 10) < 0) {
                throw new JsonException("invalid token at position " + pos);
            }
            if (!atEnd() && text.charAt(pos) == '-') {
                pos++;
            }
            boolean isDouble = false;
            while (!atEnd()) {
                char c = text.charAt(pos);
                if (c >= '0' && c <= '9') {
                    pos++;
                } else if (c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') {
                    isDouble = true;
                    pos++;
                } else {
                    break;
                }
            }
            String raw = text.substring(start, pos);
            if (raw.isEmpty() || raw.equals("-")) {
                throw new JsonException("invalid number at position " + start);
            }
            try {
                return isDouble ? (Object) Double.parseDouble(raw) : (Object) Long.parseLong(raw);
            } catch (NumberFormatException ex) {
                throw new JsonException("invalid number: " + raw);
            }
        }
    }
}
