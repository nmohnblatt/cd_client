package main

type server struct {
	ID   string
	addr string
}

func newServer(name string, addr string) *server {
	s := server{name, addr}
	return &s
}
