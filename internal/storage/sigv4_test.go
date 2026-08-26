package storage

// The SigV4 primitives are pinned against the official AWS documented
// example (the canonical GET example from the Signature Version 4
// documentation, using the well-known AKIDEXAMPLE credentials). A
// hand-rolled signer is only trustworthy if it reproduces a published
// vector byte for byte: every intermediate document is asserted, not just
// the final signature, so a regression points at the exact stage that broke.

import (
	"strings"
	"testing"
	"time"
)

const (
	exampleAccessKey = "AKIDEXAMPLE"
	exampleSecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	exampleRegion    = "us-east-1"
	exampleService   = "iam"

	// The expected documents, verbatim from the AWS documentation.
	wantCanonicalRequest = "GET\n" +
		"/\n" +
		"Action=ListUsers&Version=2010-05-08\n" +
		"content-type:application/x-www-form-urlencoded; charset=utf-8\n" +
		"host:iam.amazonaws.com\n" +
		"x-amz-date:20150830T123600Z\n" +
		"\n" +
		"content-type;host;x-amz-date\n" +
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	wantStringToSign = "AWS4-HMAC-SHA256\n" +
		"20150830T123600Z\n" +
		"20150830/us-east-1/iam/aws4_request\n" +
		"f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59"

	wantSignature = "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
)

// exampleTime is the timestamp the AWS example signs under.
func exampleTime() time.Time {
	return time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
}

func exampleHeaders() map[string]string {
	return map[string]string{
		"Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
		"Host":         "iam.amazonaws.com",
		"X-Amz-Date":   "20150830T123600Z",
	}
}

func TestSigV4CanonicalRequestMatchesAWSExample(t *testing.T) {
	got, signed := canonicalRequest(
		"GET", "/", "Action=ListUsers&Version=2010-05-08",
		exampleHeaders(), emptyPayloadHash)

	if got != wantCanonicalRequest {
		t.Errorf("canonical request mismatch\n got: %q\nwant: %q", got, wantCanonicalRequest)
	}
	if want := "content-type;host;x-amz-date"; signed != want {
		t.Errorf("signed headers = %q, want %q", signed, want)
	}
}

func TestSigV4StringToSignMatchesAWSExample(t *testing.T) {
	got := stringToSign(exampleTime(), exampleRegion, exampleService, wantCanonicalRequest)
	if got != wantStringToSign {
		t.Errorf("string to sign mismatch\n got: %q\nwant: %q", got, wantStringToSign)
	}
}

func TestSigV4CredentialScopeMatchesAWSExample(t *testing.T) {
	got := credentialScope(exampleTime(), exampleRegion, exampleService)
	if want := "20150830/us-east-1/iam/aws4_request"; got != want {
		t.Errorf("credential scope = %q, want %q", got, want)
	}
}

// TestSigV4SignatureMatchesAWSExample is the vector that matters: the full
// chain, from the raw secret to the hex signature AWS publishes.
func TestSigV4SignatureMatchesAWSExample(t *testing.T) {
	key := signingKey(exampleSecretKey, exampleTime(), exampleRegion, exampleService)
	got := signature(key, wantStringToSign)
	if got != wantSignature {
		t.Errorf("signature = %q, want %q", got, wantSignature)
	}
}

// TestSigV4EndToEndFromPrimitives runs the primitives in the order the
// driver runs them, so a mistake in the sequencing (not just in one stage)
// is caught too.
func TestSigV4EndToEndFromPrimitives(t *testing.T) {
	tm := exampleTime()
	canonical, signed := canonicalRequest(
		"GET", "/", "Action=ListUsers&Version=2010-05-08",
		exampleHeaders(), emptyPayloadHash)
	sts := stringToSign(tm, exampleRegion, exampleService, canonical)
	sig := signature(signingKey(exampleSecretKey, tm, exampleRegion, exampleService), sts)

	if sig != wantSignature {
		t.Fatalf("end-to-end signature = %q, want %q", sig, wantSignature)
	}
	if !strings.Contains(sts, credentialScope(tm, exampleRegion, exampleService)) {
		t.Errorf("string to sign is missing the credential scope: %q", sts)
	}
	if signed != "content-type;host;x-amz-date" {
		t.Errorf("signed headers = %q", signed)
	}
}

// TestSigV4SigningKeyIsScoped guards the derivation chain: changing the day,
// the region or the service must change the key. If any link were dropped, a
// signature would be replayable outside its scope.
func TestSigV4SigningKeyIsScoped(t *testing.T) {
	base := signingKey(exampleSecretKey, exampleTime(), exampleRegion, exampleService)

	cases := []struct {
		name    string
		t       time.Time
		region  string
		service string
	}{
		{"different day", exampleTime().AddDate(0, 0, 1), exampleRegion, exampleService},
		{"different region", exampleTime(), "eu-central-1", exampleService},
		{"different service", exampleTime(), exampleRegion, "s3"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			other := signingKey(exampleSecretKey, tc.t, tc.region, tc.service)
			if string(other) == string(base) {
				t.Errorf("signing key did not change for %s", tc.name)
			}
		})
	}
	// The time of day must NOT matter - the key is per-day.
	sameDay := signingKey(exampleSecretKey, exampleTime().Add(3*time.Hour), exampleRegion, exampleService)
	if string(sameDay) != string(base) {
		t.Error("signing key changed within the same UTC day")
	}
}

func TestCanonicalRequestHeaderCanonicalization(t *testing.T) {
	// SigV4 requires trimmed values with internal space runs collapsed, and
	// header names lowercased and sorted.
	got, signed := canonicalRequest("PUT", "/o", "", map[string]string{
		"X-Amz-Date": "  20150830T123600Z  ",
		"Host":       "example.com",
		"X-Amz-Meta": "a    b   c",
	}, emptyPayloadHash)

	if want := "host;x-amz-date;x-amz-meta"; signed != want {
		t.Errorf("signed headers = %q, want %q", signed, want)
	}
	if !strings.Contains(got, "x-amz-date:20150830T123600Z\n") {
		t.Errorf("value was not trimmed: %q", got)
	}
	if !strings.Contains(got, "x-amz-meta:a b c\n") {
		t.Errorf("internal spaces were not collapsed: %q", got)
	}
}

func TestURIEncodePath(t *testing.T) {
	cases := map[string]string{
		"":                "/",
		"/":               "/",
		"/bucket/key-1.x": "/bucket/key-1.x",
		"/a b":            "/a%20b",
		"/a+b":            "/a%2Bb",
		"/~_.-":           "/~_.-",
	}
	for in, want := range cases {
		if got := uriEncodePath(in); got != want {
			t.Errorf("uriEncodePath(%q) = %q, want %q", in, got, want)
		}
	}
}
