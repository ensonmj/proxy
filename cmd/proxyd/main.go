package main

import (
	"log"
	"sync"

	"github.com/ensonmj/proxy"
	"github.com/spf13/pflag"
)

func main() {
	fChainNodes := pflag.StringSliceP("Forward", "f", nil,
		"forward address, can make a forward chain")
	fLocalNodes := pflag.StringSliceP("Listen", "l", []string{"127.0.0.1:8088"},
		"listen address, can listen on multiple ports")
	fVerbose := pflag.IntP("Verbose", "v", 0, "log level")

	pflag.Parse()

	if *fVerbose < 0 || *fVerbose > 6 {
		*fVerbose = 3
	}
	proxy.SetLevel(*fVerbose)

	var wg sync.WaitGroup
	for _, strNode := range *fLocalNodes {
		asyncListenAndServe(&wg, strNode, *fChainNodes...)
	}
	wg.Wait()
}

func asyncListenAndServe(wg *sync.WaitGroup, localURL string, chainURL ...string) {
	srv, err := proxy.NewServer(localURL, chainURL...)
	if err != nil {
		log.Printf("%+v\n", err)
		return
	}

	wg.Add(1)
	go func(srv *proxy.Server) {
		defer wg.Done()
		log.Printf("%+v\n", srv.ListenAndServe())
	}(srv)
}
