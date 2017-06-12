package xmpp

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
)

const (
	// NsJabberClient is the constant for jabber:client
	NsJabberClient = "jabber:client"
	// NsStream is the constant for the nsstream
	NsStream = "http://etherx.jabber.org/streams"
	// NsIqAuth is the constant for nsiqauth
	NsIqAuth = "jabber:iq:auth"
	// NsIqRoster is the constant for nsiqroster
	NsIqRoster = "jabber:iq:roster"
	// NsTLS is the constant for tls
	NsTLS = "urn:ietf:params:xml:ns:xmpp-tls"
	// NsDisco is the constanct for nsdisco
	NsDisco = "http://jabber.org/protocol/disco#items"
	// NsMuc is the constant for muc
	NsMuc = "http://jabber.org/protocol/muc"

	xmlStream      = "<stream:stream from='%s' to='%s' version='1.0' xml:lang='en' xmlns='%s' xmlns:stream='%s'>"
	xmlStartTLS    = "<starttls xmlns='%s'/>"
	xmlIqSet       = "<iq type='set' id='%s'><query xmlns='%s'><username>%s</username><password>%s</password><resource>%s</resource></query></iq>"
	xmlIqGet       = "<iq from='%s' to='%s' id='%s' type='get'><query xmlns='%s'/></iq>"
	xmlPresence    = "<presence from='%s'><show>%s</show></presence>"
	xmlMUCPart     = "<presence to='%s' type='unavailable'></presence>"
	xmlMUCPresence = "<presence id='%s' to='%s' from='%s'><x xmlns='%s'/></presence>"
	xmlMUCMessage  = "<message from='%s' id='%s' to='%s' type='%s'><body>%s</body></message>"
)

type required struct{}

type features struct {
	XMLName    xml.Name  `xml:"features"`
	StartTLS   *required `xml:"starttls>required"`
	Mechanisms []string  `xml:"mechanisms>mechanism"`
}

type item struct {
	Email           string `xml:"email,attr"`
	Jid             string `xml:"jid,attr"`
	LastActive      string `xml:"x>last_active"`
	MentionName     string `xml:"mention_name,attr"`
	Name            string `xml:"name,attr"`
	NumParticipants string `xml:"x>num_participants"`
	Owner           string `xml:"x>owner"`
	Privacy         string `xml:"x>privacy"`
	RoomId          string `xml:"x>id"`
	Topic           string `xml:"x>topic"`
}

// Ack is a message ack
type Ack struct {
	Ack string `xml:"a"`
}

type query struct {
	XMLName xml.Name `xml:"query"`
	Items   []*item  `xml:"item"`
}

type body struct {
	Body string `xml:",innerxml"`
}

// Conn represents a connection
type Conn struct {
	incoming *xml.Decoder
	outgoing net.Conn
	errchan  chan error
}

// Message represents a message
type Message struct {
	Jid         string
	MentionName string
	Body        string
}

// Stream is the stream function on a connection
func (c *Conn) Stream(jid, host string) {
	if _, err := fmt.Fprintf(c.outgoing, xmlStream, jid, host, NsJabberClient, NsStream); err != nil {
		c.errchan <- err
	}
}

// StartTLS is the tls start function on a connection
func (c *Conn) StartTLS() {
	if _, err := fmt.Fprintf(c.outgoing, xmlStartTLS, NsTLS); err != nil {
		c.errchan <- err
	}
}

// UseTLS uses TLS with the specified host
func (c *Conn) UseTLS(host string) {
	c.outgoing = tls.Client(c.outgoing, &tls.Config{ServerName: host})
	c.incoming = xml.NewDecoder(c.outgoing)
}

// Auth authentications with given credentials as a resource
func (c *Conn) Auth(user, pass, resource string) {
	if _, err := fmt.Fprintf(c.outgoing, xmlIqSet, id(), NsIqAuth, user, pass, resource); err != nil {
		c.errchan <- err
	}
}

// Features returns features
func (c *Conn) Features() *features {
	var f features
	if err := c.incoming.DecodeElement(&f, nil); err != nil {
		c.errchan <- err
	}
	return &f
}

// Next reads the next message from a stream
func (c *Conn) Next() (xml.StartElement, error) {

	for {
		var element xml.StartElement
		var err error
		var t xml.Token
		t, err = c.incoming.Token()
		if err != nil {
			return element, err
		}

		switch t := t.(type) {
		case xml.StartElement:
			element = t
			if element.Name.Local == "" {
				return element, errors.New("invalid xml response")
			}
			return element, nil
		}
	}
}

// Discover discovers
func (c *Conn) Discover(from, to string) {
	if _, err := fmt.Fprintf(c.outgoing, xmlIqGet, from, to, id(), NsDisco); err != nil {
		c.errchan <- err
	}
}

// Body gets the body of a message
func (c *Conn) Body() string {
	b := new(body)
	if err := c.incoming.DecodeElement(b, nil); err != nil {
		c.errchan <- err
	}
	return b.Body
}

// Query issues a query
func (c *Conn) Query() *query {
	q := new(query)
	if err := c.incoming.DecodeElement(q, nil); err != nil {
		c.errchan <- err
	}
	return q
}

// Presence sets a presence
func (c *Conn) Presence(jid, pres string) {
	if _, err := fmt.Fprintf(c.outgoing, xmlPresence, jid, pres); err != nil {
		c.errchan <- err
	}
}

// MUCPart leaves a muc
func (c *Conn) MUCPart(roomId string) {
	if _, err := fmt.Fprintf(c.outgoing, xmlMUCPart, roomId); err != nil {
		c.errchan <- err
	}
}

// MUCPresence sets a muc presence
func (c *Conn) MUCPresence(roomId, jid string) {
	if _, err := fmt.Fprintf(c.outgoing, xmlMUCPresence, id(), roomId, jid, NsMuc); err != nil {
		c.errchan <- err
	}
}

// MUCSend sends a message to a muc
func (c *Conn) MUCSend(mtype, to, from, body string) {
	if _, err := fmt.Fprintf(c.outgoing, xmlMUCMessage, from, id(), to, mtype, html.EscapeString(body)); err != nil {
		c.errchan <- err
	}
}

// Roster gets the roster
func (c *Conn) Roster(from, to string) {
	if _, err := fmt.Fprintf(c.outgoing, xmlIqGet, from, to, id(), NsIqRoster); err != nil {
		c.errchan <- err
	}
}

// KeepAlive sets a keepalive
// we exit here to allow for handling of cases where we can't write to the xmpp server
// so the user can decide
func (c *Conn) KeepAlive() error {
	if _, err := fmt.Fprintf(c.outgoing, " "); err != nil {
		return err
	}
	return nil
}

// SetErrorChannel sets the channel for handling errors
func (c *Conn) SetErrorChannel(channel chan error) {
	c.errchan = channel
}

// Dial dials an xmpp host
func Dial(host string) (*Conn, error) {
	c := new(Conn)
	outgoing, err := net.Dial("tcp", host+":5222")

	if err != nil {
		return c, err
	}

	c.outgoing = outgoing
	c.incoming = xml.NewDecoder(outgoing)

	return c, nil
}

// ToMap converts an xmpp message's xml to a map
func ToMap(attr []xml.Attr) map[string]string {
	m := make(map[string]string)
	for _, a := range attr {
		m[a.Name.Local] = a.Value
	}

	return m
}

func id() string {
	b := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		fmt.Printf("error generating id: %s", err.Error())
	}
	return fmt.Sprintf("%x", b)
}
