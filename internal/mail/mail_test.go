package mail

import (
	"testing"
)

type mockSMTPMailer struct {
	SentTo      string
	SentSubject string
	SentBody    string
	SentHTML    string
}

func (m *mockSMTPMailer) Send(to, subject, body string) error {
	m.SentTo = to
	m.SentSubject = subject
	m.SentBody = body
	return nil
}

func (m *mockSMTPMailer) SendHTML(to, subject, htmlBody string) error {
	m.SentTo = to
	m.SentSubject = subject
	m.SentHTML = htmlBody
	return nil
}

func TestSMTPMailer_Send(t *testing.T) {
	mailer := &mockSMTPMailer{}

	to := "user@example.com"
	subject := "Test Subject"
	body := "Hello, this is a test."
	err := mailer.Send(to, subject, body)
	if err != nil {
		t.Errorf("Send returned error: %v", err)
	}
	if mailer.SentTo != to || mailer.SentSubject != subject || mailer.SentBody != body {
		t.Errorf("Send did not set fields correctly")
	}
}

func TestSMTPMailer_SendHTML(t *testing.T) {
	mailer := &mockSMTPMailer{}

	to := "user@example.com"
	subject := "HTML Subject"
	htmlBody := "<h1>Hello</h1><p>This is a test.</p>"
	err := mailer.SendHTML(to, subject, htmlBody)
	if err != nil {
		t.Errorf("SendHTML returned error: %v", err)
	}
	if mailer.SentTo != to || mailer.SentSubject != subject || mailer.SentHTML != htmlBody {
		t.Errorf("SendHTML did not set fields correctly")
	}
}
