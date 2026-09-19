package main

import "golang.org/x/sys/unix"

func macOSInfo() (product, build string) {
	product, err := unix.Sysctl("kern.osproductversion")
	if err != nil || product == "" {
		product = "unknown"
	}
	build, err = unix.Sysctl("kern.osversion")
	if err != nil || build == "" {
		build = "unknown"
	}
	return product, build
}
