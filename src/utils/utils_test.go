package utils

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestExpandEnvironmentVariableStringFromEnv(t *testing.T) {
	t.Setenv("TEST_EXPAND_ENV_VAR", "value-from-env")

	result := ExpandEnvironmentVariableString("${TEST_EXPAND_ENV_VAR}")

	if result != "value-from-env" {
		t.Fatalf("expected value-from-env, got %s", result)
	}
}

func TestExpandEnvironmentVariableStringFromFile(t *testing.T) {
	secretFile := filepath.Join(t.TempDir(), "secret")

	if err := os.WriteFile(secretFile, []byte("value-from-file\n"), 0600); err != nil {
		t.Fatal(err)
	}

	result := ExpandEnvironmentVariableString("${file:" + secretFile + "}")

	if result != "value-from-file" {
		t.Fatalf("expected value-from-file, got %s", result)
	}
}

func TestExpandEnvironmentVariableStringFromMissingFile(t *testing.T) {
	value := "${file:/no/such/file}"

	result := ExpandEnvironmentVariableString(value)

	if result != value {
		t.Fatalf("expected the original value to be returned unchanged, got %s", result)
	}
}

func TestChunkString(t *testing.T) {
	originalText := "abcdefghijklmnopqrstuvwxyz"

	chunks := ChunkString(originalText, 10)

	if len(chunks) != 3 {
		t.Fail()
	}

	value := ""

	for i := 0; i < len(chunks); i++ {
		value += chunks[i]
	}

	if value != originalText {
		t.Fail()
	}
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	secret := "MLFs4TT99kOOq8h3UAVRtYoCTDYXiRcZ"
	originalText := "hello"

	encrypted, err := Encrypt(originalText, secret)
	if err != nil {
		t.Fail()
	}

	decrypted, err := Decrypt(encrypted, secret)
	if err != nil {
		t.Fail()
	}

	if decrypted != originalText {
		t.Fail()
	}
}

func TestDecryptEmptyString(t *testing.T) {
	secret := "MLFs4TT99kOOq8h3UAVRtYoCTDYXiRcZ"

	_, err := Decrypt("", secret)

	// Must return an error
	if err == nil {
		t.Fail()
	}
}

func TestValidateRedirectUri(t *testing.T) {
	validUris := []string{
		"/",
		"https://example.com",
		"https://something.com",
	}

	expectRedirectUriMatch(t, "https://example.com", validUris, true)
	expectRedirectUriMatch(t, "https://malicious.com", validUris, false)
}

func TestValidateRedirectUriWildcards(t *testing.T) {
	validUris := []string{
		"/",
		"https://example.com",
		"https://something.com",
		"*",
	}

	expectRedirectUriMatch(t, "https://malicious.com", validUris, true)

	validUris = []string{
		"https://example.com",
		"https://*.something.com",
		"https://*.something.com/good",
		"https://*.something.com/good/*",
	}

	expectRedirectUriMatch(t, "https://app.something.com", validUris, true)
	expectRedirectUriMatch(t, "https://app.sub.something.com", validUris, false)
	expectRedirectUriMatch(t, "https://app.something.com/login", validUris, false)
	expectRedirectUriMatch(t, "https://app.something.com/good", validUris, true)
	expectRedirectUriMatch(t, "https://app.something.com/good/something", validUris, true)

	// A trailing "*" matches everything below the prefix, no matter how many segments
	// it spans or whether the last one contains a dot.
	expectRedirectUriMatch(t, "https://app.something.com/good/something/bad", validUris, true)
	expectRedirectUriMatch(t, "https://app.something.com/index.html", validUris, false)
	expectRedirectUriMatch(t, "https://app.something.com/good/index.html", validUris, true)

	// The query string is not part of the comparison once a wildcard is in play.
	expectRedirectUriMatch(t, "https://app.something.com/good/something?a=1", validUris, true)

	// A path that walks up the tree never matches a wildcard, in any encoding.
	expectRedirectUriMatch(t, "https://app.something.com/good/../../etc/passwd", validUris, false)
	expectRedirectUriMatch(t, "https://app.something.com/good/%2e%2e%2f%2e%2e/etc", validUris, false)

	// Neither does a uri hiding the real host behind user-info.
	expectRedirectUriMatch(t, "https://app.something.com@malicious.com/good/x", validUris, false)
}

func TestValidateRedirectUriRejectsGluedHostWildcard(t *testing.T) {
	// A "*" glued directly onto the host with nothing after it (a likely missing "/" before
	// an intended path wildcard) must never be treated as a host-label wildcard.
	validUris := []string{"https://good.example.com*"}

	expectRedirectUriMatch(t, "https://good.example.com/anything", validUris, false)
	expectRedirectUriMatch(t, "https://good.example.comEVIL", validUris, false)
	expectRedirectUriMatch(t, "https://good.example.com*", validUris, true)

	// A lone "*" as the whole host is still a legitimate, unambiguous single-label wildcard.
	expectRedirectUriMatch(t, "https://localhost", []string{"https://*"}, true)
	expectRedirectUriMatch(t, "https://app.example.com", []string{"https://*"}, false)

	// A "*" right after ":" is unambiguously a port wildcard, not a missing "/" -- a path
	// separator wouldn't make sense there, so it's still honored. The template has no path
	// of its own, so it only matches a value with no path either -- a value with a path
	// needs "https://good.example.com:*/*" instead.
	expectRedirectUriMatch(t, "https://good.example.com:8443", []string{"https://good.example.com:*"}, true)
	expectRedirectUriMatch(t, "https://good.example.com:8443/app", []string{"https://good.example.com:*"}, false)
}

func TestValidateRedirectUriPathOnlyWildcards(t *testing.T) {
	validUris := []string{
		"/app/*",
	}

	expectRedirectUriMatch(t, "/app/index.html", validUris, true)
	expectRedirectUriMatch(t, "/app/something", validUris, true)
	expectRedirectUriMatch(t, "/app/sub/index.html", validUris, true)

	// A URL-encoded space ("%20") is just a run of literal "%", "2", "0" characters as far
	// as the matcher is concerned - no decoding happens, but it still matches "*" since none
	// of them is a "/".
	expectRedirectUriMatch(t, "/app/index%20with%20space.html", validUris, true)

	// The prefix itself is matched as well, so "/app/*" matches "/app".
	expectRedirectUriMatch(t, "/app", validUris, true)

	// An SPA using hash routing right at the prefix boundary still matches "/app/*", and the
	// hash route plus any query string on it are carried through into the accepted value
	// unchanged, even though they're ignored for the purpose of matching.
	expectRedirectUriMatch(t, "/app/#/dashboard?tab=settings", validUris, true)

	expectRedirectUriMatch(t, "/other/index.html", validUris, false)
	expectRedirectUriMatch(t, "/app/../secret", validUris, false)

	// A path-only template never matches an absolute url and vice versa.
	expectRedirectUriMatch(t, "https://malicious.com/app/index.html", validUris, false)

	// A protocol-relative "//host/path" reference resolves to a foreign host in a browser,
	// even though it has no "://" and so looks like a bare path to splitSchemeAuthorityPath.
	expectRedirectUriMatch(t, "//malicious.com/app/index.html", validUris, false)
}

func TestValidateRedirectUriKeepsFragment(t *testing.T) {
	// The fragment is only ignored for the purpose of matching against a wildcard (eg. an
	// SPA using hash routing shouldn't need a dedicated entry per route) -- it's otherwise
	// carried through unchanged into the accepted value, same as the query string already is.
	matchedUri, err := ValidateRedirectUri("https://example.com/app#/page", []string{"*"})

	if err != nil {
		t.Fatal(err)
	}

	if matchedUri != "https://example.com/app#/page" {
		t.Fatalf("expected the fragment to be kept, got %q", matchedUri)
	}
}

func expectRedirectUriMatch(t *testing.T, uri string, validUris []string, shouldMatch bool) {
	matchedUri, err := ValidateRedirectUri(uri, validUris)

	if (shouldMatch && err != nil) || (!shouldMatch && err == nil) {
		t.Fail()
	}

	if (shouldMatch && matchedUri != uri) || (!shouldMatch && matchedUri != "") {
		t.Fail()
	}
}

func TestParseAcceptType(t *testing.T) {
	acceptType := ParseAcceptType("text/html")
	if acceptType.Type != "text/html" {
		t.Fail()
	}
	if acceptType.Weight != 1.0 {
		t.Fail()
	}

	acceptType = ParseAcceptType("text/html;q=0.8")
	if acceptType.Type != "text/html" {
		t.Fail()
	}
	if acceptType.Weight != 0.8 {
		t.Fail()
	}

	acceptType = ParseAcceptType("application/json; q=0.5")
	if acceptType.Type != "application/json" {
		t.Fail()
	}
	if acceptType.Weight != 0.5 {
		t.Fail()
	}

	acceptType = ParseAcceptType("text/html;q=invalid")
	if acceptType.Type != "" {
		t.Fail()
	}
	if acceptType.Weight != 0.0 {
		t.Fail()
	}

	acceptType = ParseAcceptType("*/*")
	if acceptType.Type != "*/*" {
		t.Fail()
	}
	if acceptType.Weight != 1.0 {
		t.Fail()
	}

	acceptType = ParseAcceptType("")
	if acceptType.Type != "" {
		t.Fail()
	}
	if acceptType.Weight != 0.0 {
		t.Fail()
	}
}

func TestParseAcceptHeader(t *testing.T) {
	acceptTypes := ParseAcceptHeader("text/html,application/json")
	if len(acceptTypes) != 2 {
		t.Fail()
	}
	if acceptTypes[0].Type != "text/html" {
		t.Fail()
	}
	if acceptTypes[0].Weight != 1.0 {
		t.Fail()
	}
	if acceptTypes[1].Type != "application/json" {
		t.Fail()
	}
	if acceptTypes[1].Weight != 1.0 {
		t.Fail()
	}

	acceptTypes = ParseAcceptHeader("application/json;q=0.8,text/html;q=0.9")
	if len(acceptTypes) != 2 {
		t.Fail()
	}
	if acceptTypes[0].Type != "text/html" {
		t.Fail()
	}
	if acceptTypes[0].Weight != 0.9 {
		t.Fail()
	}
	if acceptTypes[1].Type != "application/json" {
		t.Fail()
	}
	if acceptTypes[1].Weight != 0.8 {
		t.Fail()
	}

	acceptTypes = ParseAcceptHeader("*/*")
	if len(acceptTypes) != 1 {
		t.Fail()
	}
	if acceptTypes[0].Type != "*/*" {
		t.Fail()
	}
	if acceptTypes[0].Weight != 1.0 {
		t.Fail()
	}
}

func TestIsHtmlRequest(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	if !IsHtmlRequest(req) {
		t.Fail()
	}

	req, _ = http.NewRequest("GET", "/", nil)
	req.Header.Set("Accept", "application/json")
	if IsHtmlRequest(req) {
		t.Fail()
	}

	req, _ = http.NewRequest("GET", "/", nil)
	req.Header.Set("Accept", "text/html, application/json")
	if !IsHtmlRequest(req) {
		t.Fail()
	}

	req, _ = http.NewRequest("GET", "/", nil)
	req.Header.Set("Accept", "application/json;q=0.9, text/html;q=0.8")
	if IsHtmlRequest(req) {
		t.Fail()
	}

	req, _ = http.NewRequest("GET", "/", nil)
	req.Header.Set("Accept", "application/json;q=0.8, text/html;q=0.9")
	if !IsHtmlRequest(req) {
		t.Fail()
	}

	req, _ = http.NewRequest("GET", "/", nil)
	req.Header.Set("Accept", "*/*")
	if IsHtmlRequest(req) {
		t.Fail()
	}

	req, _ = http.NewRequest("GET", "/", nil)
	if IsHtmlRequest(req) {
		t.Fail()
	}
}
