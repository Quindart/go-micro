package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type trackedBody struct {
	io.Reader
	closed bool
}

func (b *trackedBody) Close() error { b.closed = true; return nil }

func TestAuthenticationResponses(t *testing.T) {
	cases := []struct {
		name           string
		upstreamStatus int
		body           string
		wantStatus     int
		wantMessage    string
	}{
		{"success", 202, `{"error":false,"data":{"id":1}}`, 202, "Authenticated"},
		{"unauthorized", 401, `{"error":true,"message":"denied"}`, 401, "invalid credentials"},
		{"upstream failure", 500, `unavailable`, 400, "error authentication service"},
		{"application error", 202, `{"error":true,"message":"account disabled"}`, 401, "account disabled"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := &trackedBody{Reader: strings.NewReader(tc.body)}
			original := http.DefaultTransport
			http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tc.upstreamStatus, Body: body, Header: make(http.Header)}, nil
			})
			t.Cleanup(func() { http.DefaultTransport = original })
			w := httptest.NewRecorder()
			app := &Config{}
			app.authenticate(w, httptest.NewRequest("POST", "/handle", nil), AuthPayload{})
			var got jsonResponse
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatalf("expected exactly one JSON response, got %q: %v", w.Body.String(), err)
			}
			if w.Code != tc.wantStatus || got.Message != tc.wantMessage || got.Error != (tc.wantStatus != 202) {
				t.Errorf("status=%d response=%+v", w.Code, got)
			}
			if !body.closed {
				t.Error("upstream response body was not closed")
			}
		})
	}
}

func TestHandleRouteDecodesAuth(t *testing.T) {
	original := http.DefaultTransport
	called := false
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		called = true
		var got AuthPayload
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		if got.Email != "admin@example.com" || got.Password != "secret" {
			t.Errorf("auth=%+v", got)
		}
		return &http.Response{StatusCode: 202, Body: io.NopCloser(strings.NewReader(`{"error":false,"data":{"id":1}}`)), Header: make(http.Header)}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = original })
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/handle", strings.NewReader(`{"action":"auth","auth":{"email":"admin@example.com","password":"secret"}}`))
	app := &Config{}
	app.routes().ServeHTTP(w, r)
	if w.Code != 202 || !json.Valid(w.Body.Bytes()) || !called {
		t.Fatalf("status=%d called=%v body=%q", w.Code, called, w.Body.String())
	}
}
