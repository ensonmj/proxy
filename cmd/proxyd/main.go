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
	fRevURL := pflag.StringP("Reverse", "r", "",
		`reverse proxy client listen address, or server auth info.
caution: we specify client end listen address in server end`)
	fVerbose := pflag.IntP("Verbose", "v", 0, "log level")

	pflag.Parse()

	if *fVerbose < 0 || *fVerbose > 6 {
		*fVerbose = 3
	}
	proxy.SetLevel(*fVerbose)

	// reverse proxy
	// ************************************************************************
	// server --> server end proxy ... tunnel ... client end proxy --> client
	// ************************************************************************
	if *fRevURL != "" {
		if len(*fChainURLs) <= 0 {
			log.Printf("reverse proxy must cowork with \"Forward\" nodes")
			return
		}
		revServe(*fRevURL, *fChainURLs...)
		return
	}

	listenAndServe(*fLocalURL, *fChainURLs...)
}

func listenAndServe(localURL string, chainURL ...string) {
	srv, err := proxy.NewServer(localURL, chainURL...)
	if err != nil {
		log.Printf("%+v\n", err)
		return
	}

	log.Printf("%+v\n", srv.ListenAndServe())
}

func revServe(revURL string, chainURL ...string) {
	srv, err := proxy.NewServer(revURL, chainURL...)
	if err != nil {
		log.Printf("%+v\n", err)
		return
	}

	log.Printf("%+v\n", srv.RevServe())

}
