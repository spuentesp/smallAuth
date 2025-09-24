package mail

import (
	"fmt"
	"net/smtp"

	"github.com/example/smallauth/internal/config"
)

// Mailer interface for sending emails
// Allows for future extension (e.g., Brevo API)
type Mailer interface {
	Send(to, subject, body string) error
	SendHTML(to, subject, htmlBody string) error
}

// SMTPMailer implements Mailer using SMTP relay

type SMTPMailer struct {
	cfg *config.Config
}

func NewSMTPMailer(cfg *config.Config) *SMTPMailer {
	return &SMTPMailer{cfg: cfg}
}

func (m *SMTPMailer) Send(to, subject, body string) error {
	from := m.cfg.SMTPUser
	host := m.cfg.SMTPHost
	port := m.cfg.SMTPPort
	addr := fmt.Sprintf("%s:%s", host, port)

	auth := smtp.PlainAuth("", m.cfg.SMTPUser, m.cfg.SMTPPassword, host)

	msg := []byte(fmt.Sprintf("To: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s", to, subject, body))
	return smtp.SendMail(addr, auth, from, []string{to}, msg)
}

// SendHTML sends an HTML email using SMTP
func (m *SMTPMailer) SendHTML(to, subject, htmlBody string) error {
	from := m.cfg.SMTPUser
	host := m.cfg.SMTPHost
	port := m.cfg.SMTPPort
	addr := fmt.Sprintf("%s:%s", host, port)

	auth := smtp.PlainAuth("", m.cfg.SMTPUser, m.cfg.SMTPPassword, host)

	msg := []byte(fmt.Sprintf("To: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s", to, subject, htmlBody))
	return smtp.SendMail(addr, auth, from, []string{to}, msg)
}
