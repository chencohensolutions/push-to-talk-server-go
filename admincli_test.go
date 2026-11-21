package main

import (
	"strings"
	"testing"
)

func TestEnrollmentLink(t *testing.T) {
	server := "https://ptt.example.com:56400"
	if got, want := enrollmentLink("K7QM-4XPD", &server, nil), "ptt://enroll?code=K7QM-4XPD&server=https%3A%2F%2Fptt.example.com%3A56400"; got != want {
		t.Errorf("enrollmentLink = %q, want %q", got, want)
	}
	// Without public_url the app keeps the address it has.
	if got, want := enrollmentLink("K7QM-4XPD", nil, nil), "ptt://enroll?code=K7QM-4XPD"; got != want {
		t.Errorf("enrollmentLink = %q, want %q", got, want)
	}
	// With who the server is and where: the phone pins the key and can look the server up.
	found := &enrollDiscovery{Fingerprint: "ab12", Key: "cd34", Addresses: []string{"https://203.0.113.7:56400", "https://192.168.1.20:56400"}}
	if got, want := enrollmentLink("K7QM-4XPD", &server, found), "ptt://enroll?address=https%3A%2F%2F203.0.113.7%3A56400&address=https%3A%2F%2F192.168.1.20%3A56400&code=K7QM-4XPD&fingerprint=ab12&key=cd34&server=https%3A%2F%2Fptt.example.com%3A56400"; got != want {
		t.Errorf("enrollmentLink = %q, want %q", got, want)
	}
	// At most 6 addresses.
	found.Addresses = []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	if got := enrollmentLink("K7QM-4XPD", nil, found); len(found.Addresses) != 8 || strings.Contains(got, "address=g") {
		t.Errorf("enrollmentLink = %q", got)
	}
}
