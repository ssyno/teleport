package services

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"path/filepath"

	"github.com/gravitational/trace"
	"github.com/siddontang/go/log"
)

type WebassetCache struct {
	webassets map[string][]byte
}

func NewWebassetCache(ctx context.Context) (*WebassetCache, error) {
	return &WebassetCache{
		webassets: make(map[string][]byte),
	}, nil
}

func (c *WebassetCache) GetWebasset(fileName string) ([]byte, error) {
	if fileContents, ok := c.webassets[fileName]; ok {
		//do something here
		return fileContents, nil
	}

	errorMessage := fmt.Sprintf("file %s not found", fileName)
	return nil, trace.NotFound(errorMessage)
}

// EmitWebassets is a recursive function that takes a path and the StaticFS
// from the webConfig and iterates through every file, checking it in
// to the auth webasset cache
func (c *WebassetCache) EmitWebassets(fs http.FileSystem, path string, uploadFunc func(string, []byte)) {
	file, err := fs.Open(path)
	if err != nil {
		log.Error("Error opening file: %v", err)
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		log.Error("Error reading dir %s: %v", fileInfo.Name(), err)
	}

	if fileInfo.IsDir() {
		fileInfos, err := file.Readdir(-1)
		if err != nil {
			log.Error("Error reading dir: %s: %v", fileInfo.Name(), err)
		}

		for _, fileInfo := range fileInfos {
			childPath := filepath.Join(path, fileInfo.Name())
			c.EmitWebassets(fs, childPath, uploadFunc)
		}
	} else {
		content, err := io.ReadAll(file)
		if err != nil {
			log.Errorf("Error opening file: %s: %v", fileInfo.Name(), err)
		}

		uploadFunc(fileInfo.Name(), content)
	}
}
