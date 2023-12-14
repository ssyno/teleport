package webassetcachev1

import (
	"context"

	"github.com/gravitational/teleport/api/gen/proto/go/webassetcache/v1"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/trace"
)

type ServiceConfig struct {
	Cache *services.WebassetCache
}

type Service struct {
	webassetcache.UnimplementedWebassetCacheServiceServer

	cache *services.WebassetCache
}

// NewService returns a new user preferences gRPC service.
func NewService(cfg *ServiceConfig) (*Service, error) {
	if cfg.Cache == nil {
		return nil, trace.BadParameter("cache is required")
	}

	return &Service{
		cache: cfg.Cache,
	}, nil
}

// GetWebasset
func (a *Service) GetWebasset(ctx context.Context, req *webassetcache.GetWebassetRequest) (*webassetcache.GetWebassetResponse, error) {
	fileContents, err := a.cache.GetWebasset(req.Name)

	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &webassetcache.GetWebassetResponse{
		Name:    req.Name,
		Content: fileContents,
	}, nil
}
