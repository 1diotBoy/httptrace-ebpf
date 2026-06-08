package httptrace

import (
	"bytes"
	"fmt"
	"net/textproto"
	"strconv"
	"strings"
)

const (
	DirectionUnknown  = 0
	DirectionRequest  = 1
	DirectionResponse = 2
)

var headerSeparator = []byte("\r\n\r\n")

var requestStartTokens = [][]byte{
	[]byte("GET "),
	[]byte("POST "),
	[]byte("PUT "),
	[]byte("PATCH "),
	[]byte("DELETE "),
	[]byte("HEAD "),
	[]byte("OPTIONS "),
	[]byte("TRACE "),
	[]byte("CONNECT "),
}

type ParseOptions struct {
	RequestMethod string
	EOF           bool
}

type ParsedMessage struct {
	Direction    uint8               `json:"direction"`
	StartLine    string              `json:"start_line"`
	Version      string              `json:"version,omitempty"`
	Method       string              `json:"method,omitempty"`
	URL          string              `json:"url,omitempty"`
	StatusCode   int                 `json:"status_code,omitempty"`
	Reason       string              `json:"reason,omitempty"`
	Headers      map[string]string   `json:"headers"`
	HeaderValues map[string][]string `json:"header_values,omitempty"`
	// RawHeader          string              `json:"raw_header"`
	// RawPayload         string `json:"raw_payload"`
	Body                 string `json:"body"`
	BodySizeBytes        int    `json:"body_size_bytes,omitempty"` // 单位 字节
	ObservedMessageBytes uint64 `json:"observed_message_bytes,omitempty"`
	ContentLength        int64  `json:"content_length,omitempty"`
	TransferEncoding     string `json:"transfer_encoding,omitempty"`
	Chunked              bool   `json:"chunked"`
	BodyPartial          bool   `json:"body_partial,omitempty"`
	ConnectionCloseEOF   bool   `json:"connection_close_eof"`
	ConsumedBytes        int    `json:"consumed_bytes"`
}

// TryParseMessage 负责把聚合后的 HTTP 明文切成起始行、头和 body，
// 并根据 Content-Length / chunked / EOF 判断消息是否已经完整。
func TryParseMessage(direction uint8, data []byte, opts ParseOptions) (*ParsedMessage, bool, error) {
	msg, headers, bodyStart, ok, err := parseMessageHead(direction, data)
	if err != nil || !ok {
		return nil, false, err
	}

	return finalizeMessage(msg, headers, bodyStart, data, opts)
}

// TryParseMessageHead 只要求 HTTP 起始行和头部完整，就会返回一个可展示的结果。
// 这用于“响应已经拿到头，但 body 还在持续发送/被截断”的场景，避免整条响应完全没有输出。
func TryParseMessageHead(direction uint8, data []byte, opts ParseOptions) (*ParsedMessage, bool, error) {
	msg, headers, bodyStart, ok, err := parseMessageHead(direction, data)
	if err != nil || !ok {
		return nil, false, err
	}

	body := data[bodyStart:]
	// msg.RawPayload = string(data)
	msg.ConsumedBytes = len(data)

	noBody := hasNoBody(direction, msg, headers, opts)
	switch {
	case msg.Chunked:
		decoded, consumed, complete, err := decodeChunkedBody(body)
		if err != nil {
			return nil, false, err
		}
		if complete {
			msg.Body = string(decoded)
			msg.ConsumedBytes = bodyStart + consumed
			// msg.RawPayload = string(data[:msg.ConsumedBytes])
			return msg, true, nil
		}
		if len(body) > 0 {
			if preview, ok := decodeChunkedBodyPreview(body); ok {
				msg.Body = string(preview)
			} else {
				msg.Body = string(body)
			}
			msg.BodyPartial = true
		}
		return msg, true, nil
	case msg.ContentLength >= 0:
		available := len(body)
		if available > int(msg.ContentLength) {
			available = int(msg.ContentLength)
		}
		if available > 0 {
			msg.Body = string(body[:available])
		}
		msg.BodyPartial = int64(available) < msg.ContentLength
		if !msg.BodyPartial {
			msg.ConsumedBytes = bodyStart + available
			// msg.RawPayload = string(data[:msg.ConsumedBytes])
		}
		return msg, true, nil
	case noBody:
		msg.ConsumedBytes = bodyStart
		// msg.RawPayload = string(data[:bodyStart])
		return msg, true, nil
	case opts.EOF || strings.EqualFold(headers.Get("Connection"), "close"):
		msg.Body = string(body)
		msg.ConsumedBytes = len(data)
		// msg.RawPayload = string(data)
		msg.ConnectionCloseEOF = true
		return msg, true, nil
	default:
		if len(body) > 0 {
			msg.Body = string(body)
		}
		msg.BodyPartial = true
		return msg, true, nil
	}
}

// TryParsePartialHead 是针对截断捕获的一种尽力而为的回退机制，
// 在这种情况下，HTTP 开始行存在，但完整的头部终止符可能不存在。
// 当验证器友好的捕获限制在用户空间中完整的请求/响应头可用之前阻止我们时，
// 它主要由TLS路径使用。
func TryParsePartialHead(direction uint8, data []byte) (*ParsedMessage, bool, error) {
	lineEnd := bytes.Index(data, []byte("\r\n"))
	if lineEnd < 0 {
		return nil, false, nil
	}

	startLine := string(data[:lineEnd])
	headers := make(textproto.MIMEHeader)
	cursor := lineEnd + 2
	bodyStart := len(data)
	for cursor < len(data) {
		next := bytes.Index(data[cursor:], []byte("\r\n"))
		if next < 0 {
			break
		}
		if next == 0 {
			bodyStart = cursor + 2
			break
		}
		line := string(data[cursor : cursor+next])
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(parts[0]))
			value := strings.TrimSpace(parts[1])
			headers.Add(key, value)
		}
		cursor += next + 2
	}

	msg := &ParsedMessage{
		Direction:     direction,
		StartLine:     startLine,
		Headers:       flattenHeaders(headers),
		HeaderValues:  cloneHeaders(headers),
		ContentLength: -1,
		ConsumedBytes: len(data),
	}
	if raw := headers.Get("Content-Length"); raw != "" {
		if v, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64); err == nil {
			msg.ContentLength = v
		}
	}
	msg.TransferEncoding = headers.Get("Transfer-Encoding")
	msg.Chunked = strings.Contains(strings.ToLower(msg.TransferEncoding), "chunked")

	switch direction {
	case DirectionRequest:
		if err := parseRequestLine(startLine, msg); err != nil {
			return nil, false, err
		}
	case DirectionResponse:
		if err := parseStatusLine(startLine, msg); err != nil {
			return nil, false, err
		}
	default:
		return nil, false, fmt.Errorf("unsupported direction %d", direction)
	}

	if bodyStart < len(data) {
		body := data[bodyStart:]
		if msg.Chunked {
			if decoded, consumed, complete, err := decodeChunkedBody(body); err == nil && complete {
				msg.Body = string(decoded)
				msg.BodySizeBytes = len(msg.Body)
				msg.BodyPartial = false
				msg.ConsumedBytes = bodyStart + consumed
				return msg, true, nil
			}
			if preview, ok := decodeChunkedBodyPreview(body); ok {
				msg.Body = string(preview)
			} else {
				msg.Body = string(body)
			}
		} else {
			msg.Body = string(body)
		}
		msg.BodySizeBytes = len(msg.Body)
		msg.BodyPartial = true
	} else if msg.ContentLength > 0 || msg.Chunked || msg.TransferEncoding != "" {
		msg.BodyPartial = true
	}
	return msg, true, nil
}

// FindMessageStart 在 buffer 里寻找下一个可信的 HTTP 消息起点。
// 这用于 keep-alive 高并发场景下少量前导脏字节把解析器"卡死"时做重同步。
func FindMessageStart(direction uint8, data []byte) int {
	switch direction {
	case DirectionRequest:
		for i := 0; i < len(data); i++ {
			for _, token := range requestStartTokens {
				if len(data[i:]) >= len(token) && bytes.HasPrefix(data[i:], token) {
					return i
				}
			}
		}
	case DirectionResponse:
		for i := 0; i < len(data); i++ {
			if len(data[i:]) >= 5 && bytes.HasPrefix(data[i:], []byte("HTTP/")) {
				return i
			}
		}
	}
	return -1
}

// BuildSyntheticResponse 在“完全没抓到 HTTP 响应头，但已经拿到响应 body”的场景下，
// 构造一条最小可用的响应对象，避免整条异常响应（404/500/认证失败页）完全丢失。
// 这条路径只用于兜底，不影响正常能解析出 HTTP 头的响应。
func BuildSyntheticResponse(data []byte) (*ParsedMessage, bool) {
	if msg, ok := buildFallbackHTTPResponse(data); ok {
		return msg, true
	}

	body := strings.TrimSpace(string(data))
	if body == "" {
		return nil, false
	}

	status, reason := inferStatusFromBody(body)
	msg := &ParsedMessage{
		Direction:  DirectionResponse,
		StartLine:  syntheticStartLine(status, reason),
		Version:    "HTTP/1.1",
		StatusCode: status,
		Reason:     reason,
		Headers:    map[string]string{},
		Body:       string(data),
		// RawPayload:    string(data),
		BodyPartial:   true,
		ConsumedBytes: len(data),
	}
	return msg, true
}

func buildFallbackHTTPResponse(data []byte) (*ParsedMessage, bool) {
	start := FindMessageStart(DirectionResponse, data)
	if start < 0 || start >= len(data) {
		return nil, false
	}
	data = data[start:]

	headerEnd := bytes.Index(data, headerSeparator)
	if headerEnd < 0 {
		return nil, false
	}

	head := string(data[:headerEnd])
	lines := strings.Split(head, "\r\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return nil, false
	}

	headers := make(map[string]string, len(lines))
	for _, line := range lines[1:] {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(parts[0]))
		headers[key] = strings.TrimSpace(parts[1])
	}

	msg := &ParsedMessage{
		Direction:        DirectionResponse,
		StartLine:        lines[0],
		Headers:          headers,
		HeaderValues:     map[string][]string{},
		ContentLength:    -1,
		TransferEncoding: headers["Transfer-Encoding"],
		Chunked:          strings.Contains(strings.ToLower(headers["Transfer-Encoding"]), "chunked"),
		Body:             string(data[headerEnd+len(headerSeparator):]),
		BodyPartial:      true,
		ConsumedBytes:    len(data),
	}
	if err := parseStatusLine(lines[0], msg); err != nil {
		status, reason := inferStatusFromBody(msg.Body)
		msg.StatusCode = status
		msg.Reason = reason
	}
	if raw := headers["Content-Length"]; raw != "" {
		if v, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64); err == nil {
			msg.ContentLength = v
		}
	}
	if msg.Chunked {
		body := data[headerEnd+len(headerSeparator):]
		if decoded, consumed, complete, err := decodeChunkedBody(body); err == nil {
			if complete {
				msg.Body = string(decoded)
				msg.BodyPartial = false
				msg.ConsumedBytes = headerEnd + len(headerSeparator) + consumed
			} else if preview, ok := decodeChunkedBodyPreview(body); ok {
				msg.Body = string(preview)
				msg.BodyPartial = true
			}
		}
	}
	return msg, true
}

func syntheticStartLine(status int, reason string) string {
	if status <= 0 {
		return "HTTP/1.1"
	}
	if reason == "" {
		return fmt.Sprintf("HTTP/1.1 %d", status)
	}
	return fmt.Sprintf("HTTP/1.1 %d %s", status, reason)
}

func inferStatusFromBody(body string) (int, string) {
	if status, ok := inferJSONStatus(body); ok {
		return status, ""
	}
	if status, reason, ok := inferHTMLStatus(body); ok {
		return status, reason
	}
	return 0, ""
}

func inferJSONStatus(body string) (int, bool) {
	idx := strings.Index(body, "\"status\"")
	if idx < 0 {
		return 0, false
	}
	rest := body[idx+len("\"status\""):]
	colon := strings.IndexByte(rest, ':')
	if colon < 0 {
		return 0, false
	}
	rest = strings.TrimSpace(rest[colon+1:])
	digits := make([]byte, 0, 3)
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		if c >= '0' && c <= '9' {
			digits = append(digits, c)
			continue
		}
		if len(digits) > 0 {
			break
		}
		if c == ' ' || c == '\t' {
			continue
		}
		return 0, false
	}
	if len(digits) != 3 {
		return 0, false
	}
	status, err := strconv.Atoi(string(digits))
	if err != nil {
		return 0, false
	}
	return status, true
}

func inferHTMLStatus(body string) (int, string, bool) {
	idx := strings.Index(body, "HTTP Status ")
	if idx < 0 {
		return 0, "", false
	}
	rest := body[idx+len("HTTP Status "):]
	if len(rest) < 3 {
		return 0, "", false
	}
	status, err := strconv.Atoi(rest[:3])
	if err != nil {
		return 0, "", false
	}
	reason := ""
	if sep := strings.Index(rest, "–"); sep >= 0 {
		reason = strings.TrimSpace(rest[sep+len("–"):])
		if end := strings.Index(reason, "<"); end >= 0 {
			reason = strings.TrimSpace(reason[:end])
		}
	}
	return status, reason, true
}

func parseMessageHead(direction uint8, data []byte) (*ParsedMessage, textproto.MIMEHeader, int, bool, error) {
	headerEnd := bytes.Index(data, headerSeparator)
	if headerEnd < 0 {
		return nil, nil, 0, false, nil
	}

	head := string(data[:headerEnd])
	// 头部明细分割
	lines := strings.Split(head, "\r\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return nil, nil, 0, false, fmt.Errorf("empty start line")
	}

	startLine := lines[0]
	headers := make(textproto.MIMEHeader)
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])
		headers.Add(key, value)
	}

	bodyStart := headerEnd + len(headerSeparator)
	msg := &ParsedMessage{
		Direction:    direction,
		StartLine:    startLine,
		Headers:      flattenHeaders(headers),
		HeaderValues: cloneHeaders(headers),
		// RawHeader:     string(data[:bodyStart]),
		ContentLength: -1,
		// RawPayload:    string(data[:bodyStart]),
		ConsumedBytes: bodyStart,
	}
	if raw := headers.Get("Content-Length"); raw != "" {
		v, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err != nil {
			return nil, nil, 0, false, fmt.Errorf("invalid Content-Length %q: %w", raw, err)
		}
		msg.ContentLength = v
	}
	msg.TransferEncoding = headers.Get("Transfer-Encoding")
	msg.Chunked = strings.Contains(strings.ToLower(msg.TransferEncoding), "chunked")

	switch direction {
	case DirectionRequest:
		if err := parseRequestLine(startLine, msg); err != nil {
			return nil, nil, 0, false, err
		}
	case DirectionResponse:
		if err := parseStatusLine(startLine, msg); err != nil {
			return nil, nil, 0, false, err
		}
	default:
		return nil, nil, 0, false, fmt.Errorf("unsupported direction %d", direction)
	}

	return msg, headers, bodyStart, true, nil
}

func finalizeMessage(msg *ParsedMessage, headers textproto.MIMEHeader, bodyStart int, data []byte, opts ParseOptions) (*ParsedMessage, bool, error) {
	noBody := hasNoBody(msg.Direction, msg, headers, opts)
	connectionClose := strings.EqualFold(headers.Get("Connection"), "close")
	switch {
	case msg.Chunked:
		body, consumed, complete, err := decodeChunkedBody(data[bodyStart:])
		if err != nil {
			return nil, false, err
		}
		if !complete {
			return nil, false, nil
		}
		msg.Body = string(body)
		msg.ConsumedBytes = bodyStart + consumed
		// msg.RawPayload = string(data[:msg.ConsumedBytes])
		return msg, true, nil
	case msg.ContentLength >= 0:
		total := bodyStart + int(msg.ContentLength)
		if len(data) < total {
			return nil, false, nil
		}
		msg.Body = string(data[bodyStart:total])
		msg.ConsumedBytes = total
		// msg.RawPayload = string(data[:total])
		return msg, true, nil
	case noBody:
		msg.ConsumedBytes = bodyStart
		// msg.RawPayload = string(data[:bodyStart])
		return msg, true, nil
	case opts.EOF || connectionClose:
		msg.Body = string(data[bodyStart:])
		msg.ConsumedBytes = len(data)
		// msg.RawPayload = string(data)
		msg.ConnectionCloseEOF = true
		return msg, true, nil
	default:
		return nil, false, nil
	}
}

func parseRequestLine(line string, msg *ParsedMessage) error {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) != 3 {
		return fmt.Errorf("malformed request line %q", line)
	}
	msg.Method = parts[0]
	msg.URL = parts[1]
	msg.Version = parts[2]
	return nil
}

func parseStatusLine(line string, msg *ParsedMessage) error {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return fmt.Errorf("malformed status line %q", line)
	}
	status, err := strconv.Atoi(parts[1])
	if err != nil {
		return fmt.Errorf("invalid status code in %q: %w", line, err)
	}
	msg.Version = parts[0]
	msg.StatusCode = status
	if len(parts) > 2 {
		msg.Reason = parts[2]
	}
	return nil
}

// decodeChunkedBody 解析 chunked body，并返回真正消耗的字节数。
func decodeChunkedBody(data []byte) ([]byte, int, bool, error) {
	var out bytes.Buffer
	cursor := 0

	for {
		lineEnd := bytes.Index(data[cursor:], []byte("\r\n"))
		if lineEnd < 0 {
			/* 抓取流可能在 chunked 结束块 "0\r\n\r\n" 上进一步少 1~2 个字节，
			 * 例如只剩 "0" 或 "0\r"。这时 body 实际已经完整，只是终止符不完整。
			 * 对这种终止块做容错，避免把完整的小响应误判成 partial。
			 */
			tail := strings.TrimSpace(string(data[cursor:]))
			if tail == "0" {
				return out.Bytes(), len(data), true, nil
			}
			return nil, 0, false, nil
		}

		line := strings.TrimSpace(string(data[cursor : cursor+lineEnd]))
		sizeToken := line
		if i := strings.Index(sizeToken, ";"); i >= 0 {
			sizeToken = sizeToken[:i]
		}
		size, err := strconv.ParseInt(sizeToken, 16, 64)
		if err != nil {
			return nil, 0, false, fmt.Errorf("invalid chunk size %q: %w", sizeToken, err)
		}
		cursor += lineEnd + 2

		if size == 0 {
			/* 部分内核/抓取路径会在 chunked 结束块 "0\r\n\r\n" 的最后一个
			 * 空行上丢 2 个字节，但此时 body 实际已经完整。对可观测性来说，
			 * 只缺最终 trailer terminator 时，优先把它视为“complete enough”，
			 * 避免把完整的小响应误标成 truncated。
			 */
			if len(data[cursor:]) == 0 {
				return out.Bytes(), cursor, true, nil
			}
			if len(data[cursor:]) < 2 {
				return nil, 0, false, nil
			}
			if bytes.HasPrefix(data[cursor:], []byte("\r\n")) {
				cursor += 2
				return out.Bytes(), cursor, true, nil
			}
			trailerEnd := bytes.Index(data[cursor:], headerSeparator)
			if trailerEnd < 0 {
				return nil, 0, false, nil
			}
			cursor += trailerEnd + len(headerSeparator)
			return out.Bytes(), cursor, true, nil
		}

		if len(data[cursor:]) < int(size)+2 {
			return nil, 0, false, nil
		}
		out.Write(data[cursor : cursor+int(size)])
		cursor += int(size)
		if !bytes.HasPrefix(data[cursor:], []byte("\r\n")) {
			/* 某些响应在 chunk body 之后会丢掉本应存在的 "\r\n"，
			 * 但终止块 "0\r\n\r\n" 已经到了。这种场景正文其实完整，
			 * 缺的仍然只是 framing，不应再判成 partial。
			 */
			switch string(data[cursor:]) {
			case "0", "0\r", "0\r\n", "0\r\n\r", "0\r\n\r\n":
				return out.Bytes(), len(data), true, nil
			}
			return nil, 0, false, fmt.Errorf("missing CRLF after chunk body")
		}
		cursor += 2
	}
}

// decodeChunkedBodyPreview best-effort strips chunk-size lines from a partial
// chunked body. It returns already-decoded body bytes collected before the
// first incomplete or malformed chunk boundary.
func decodeChunkedBodyPreview(data []byte) ([]byte, bool) {
	var out bytes.Buffer
	cursor := 0
	progress := false

	for cursor < len(data) {
		lineEnd := bytes.Index(data[cursor:], []byte("\r\n"))
		if lineEnd < 0 {
			break
		}

		line := strings.TrimSpace(string(data[cursor : cursor+lineEnd]))
		sizeToken := line
		if i := strings.Index(sizeToken, ";"); i >= 0 {
			sizeToken = sizeToken[:i]
		}
		size, err := strconv.ParseInt(sizeToken, 16, 64)
		if err != nil || size < 0 {
			break
		}
		cursor += lineEnd + 2
		if size == 0 {
			return out.Bytes(), true
		}

		available := len(data) - cursor
		if available <= 0 {
			return out.Bytes(), progress
		}
		take := int(size)
		if take > available {
			take = available
		}
		out.Write(data[cursor : cursor+take])
		progress = true
		if take < int(size) {
			return out.Bytes(), true
		}
		cursor += take
		if len(data[cursor:]) < 2 || !bytes.HasPrefix(data[cursor:], []byte("\r\n")) {
			return out.Bytes(), true
		}
		cursor += 2
	}

	return out.Bytes(), progress
}

// decodeChunkedBodyMissingOnlyFraming 判断 chunked 正文是否已经完整，
// 只是缺少最后的 framing（例如 \r\n0\r\n\r\n）。
// 返回 decoded 正文、仍缺失的 framing 字节数，以及是否命中该场景。
func decodeChunkedBodyMissingOnlyFraming(data []byte) ([]byte, int, bool) {
	var out bytes.Buffer
	cursor := 0

	for {
		lineEnd := bytes.Index(data[cursor:], []byte("\r\n"))
		if lineEnd < 0 {
			switch string(data[cursor:]) {
			case "0":
				return out.Bytes(), 4, true
			case "0\r":
				return out.Bytes(), 3, true
			case "0\r\n":
				return out.Bytes(), 2, true
			case "0\r\n\r":
				return out.Bytes(), 1, true
			default:
				return nil, 0, false
			}
		}

		line := strings.TrimSpace(string(data[cursor : cursor+lineEnd]))
		sizeToken := line
		if i := strings.Index(sizeToken, ";"); i >= 0 {
			sizeToken = sizeToken[:i]
		}
		size, err := strconv.ParseInt(sizeToken, 16, 64)
		if err != nil || size < 0 {
			return nil, 0, false
		}
		cursor += lineEnd + 2

		if size == 0 {
			rem := data[cursor:]
			switch {
			case len(rem) == 0:
				return out.Bytes(), 2, true
			case bytes.Equal(rem, []byte("\r")):
				return out.Bytes(), 1, true
			case bytes.HasPrefix(rem, []byte("\r\n")):
				return out.Bytes(), 0, true
			default:
				trailerEnd := bytes.Index(rem, headerSeparator)
				if trailerEnd >= 0 {
					return out.Bytes(), 0, true
				}
				return nil, 0, false
			}
		}

		if len(data[cursor:]) < int(size) {
			return nil, 0, false
		}
		out.Write(data[cursor : cursor+int(size)])
		cursor += int(size)

		switch {
		case len(data[cursor:]) == 0:
			return out.Bytes(), 7, true
		case bytes.Equal(data[cursor:], []byte("\r")):
			return out.Bytes(), 6, true
		case len(data[cursor:]) < 2:
			return nil, 0, false
		case !bytes.HasPrefix(data[cursor:], []byte("\r\n")):
			return nil, 0, false
		}
		cursor += 2
		if len(data[cursor:]) == 0 {
			return out.Bytes(), 5, true
		}
	}
}

func hasNoBody(direction uint8, msg *ParsedMessage, headers textproto.MIMEHeader, opts ParseOptions) bool {
	if direction == DirectionRequest {
		return headers.Get("Content-Length") == "" && headers.Get("Transfer-Encoding") == ""
	}

	if opts.RequestMethod == "HEAD" {
		return true
	}
	if msg.StatusCode >= 100 && msg.StatusCode < 200 {
		return true
	}
	if msg.StatusCode == 204 || msg.StatusCode == 304 {
		return true
	}
	return false
}

func flattenHeaders(header textproto.MIMEHeader) map[string]string {
	out := make(map[string]string, len(header))
	for k, v := range header {
		out[k] = strings.Join(v, ", ")
	}
	return out
}

func cloneHeaders(header textproto.MIMEHeader) map[string][]string {
	out := make(map[string][]string, len(header))
	for k, v := range header {
		out[k] = append([]string(nil), v...)
	}
	return out
}
