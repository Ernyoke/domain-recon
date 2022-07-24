package main

import (
	"domain-recon/internal"
	"fmt"
	"github.com/jessevdk/go-flags"
	"os"
)

// Opts struct used to store command line arguments after parsing.
type Opts struct {
	Plain  bool   `short:"p" long:"plain" description:"Show plain domains"`
	Domain string `short:"d" long:"domain" description:"Domain name" required:"true"`
	File   string `short:"f" long:"file" description:"File with words for extending wildcards" value-name:"FILE"`
}

// Main entry point.
func main() {
	opts, err := parseArgs(os.Args)
	if err != nil {
		fmt.Println(err)
		_, usage := parseArgs([]string{"-h"})
		fmt.Println(usage)
		return
	}
	if err := internal.Execute(&internal.Flags{
		Domain:      opts.Domain,
		PlainOutput: opts.Plain,
		WordsFile:   opts.File}); err != nil {
		panic(err)
		return
	}
}

// Parse input arguments. Returns an object type of Opts with the result of the parsing. The secondary return argument
// represents contains a potential error which can be encountered during argument parsing. If there are no errors, this
// return value is nil
func parseArgs(args []string) (*Opts, error) {
	opts := Opts{}

	parser := flags.NewParser(&opts, flags.HelpFlag|flags.PassDoubleDash)
	if _, err := parser.ParseArgs(args); err != nil {
		return nil, err
	}

	return &opts, nil
}
