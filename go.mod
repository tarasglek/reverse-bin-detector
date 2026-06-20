module github.com/tarasglek/reverse-bin-detector

go 1.24.4

replace github.com/tarasglek/caddy-reverse-bin/detectorschema => ../caddy-reverse-bin/detectorschema

require (
	github.com/landlock-lsm/go-landlock v0.9.0
	github.com/tarasglek/caddy-reverse-bin/detectorschema v0.0.0
)

require (
	golang.org/x/sys v0.40.0 // indirect
	kernel.org/pub/linux/libs/security/libcap/psx v1.2.77 // indirect
)
