//go:build race

package main

func init() { serverBuildFlags = []string{"-race"} }
