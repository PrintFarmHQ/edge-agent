package main

import (
	"embed"
	"io/fs"
)

//go:embed webui_dist/index.html webui_dist/assets/*
var localWebUIEmbed embed.FS

var (
	localWebUIDistFS   fs.FS
	localWebUIAssetsFS fs.FS
)

func init() {
	var err error
	localWebUIDistFS, err = fs.Sub(localWebUIEmbed, "webui_dist")
	if err != nil {
		panic(err)
	}
	localWebUIAssetsFS, err = fs.Sub(localWebUIEmbed, "webui_dist/assets")
	if err != nil {
		panic(err)
	}
}
