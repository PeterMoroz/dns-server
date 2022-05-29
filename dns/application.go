package dns

import (
	"log"
)

type Application struct {
	port int
	pathToHosts string
	
	resolver *Resolver
	server Server
}

func NewApplication(port int, pathToHosts string) Application {
	resolver := Resolver{}
	server := Server{port, &resolver}
	app := Application{port, pathToHosts, &resolver, server}
	return app
}

func (a Application) Run() {
	log.Println("Application.Run() ")
	
	a.resolver.init(a.pathToHosts)
		
	a.server.run()
}
