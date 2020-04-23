package main

import (
	"log"

	"github.com/ensonmj/proxy"
	"github.com/spf13/pflag"
)

func main() {
	fChainURLs := pflag.StringSliceP("Forward", "f", nil,
		"forward address, can make a forward chain")
	fLocalURL := pflag.StringP("Listen", "l", "", "listen address")
	fVerbose := pflag.IntP("Verbose", "v", 0, "log level")

	pflag.Parse()

	if *fVerbose < 0 || *fVerbose > 6 {
		*fVerbose = 3
	}
	proxy.SetLevel(*fVerbose)

	srv, err := proxy.NewServer(*fLocalURL, *fChainURLs...)
	if err != nil {
		log.Printf("%+v\n", err)
		return
	}

	log.Printf("%+v\n", srv.Serve())
}
