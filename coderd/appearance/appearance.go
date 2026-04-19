package appearance

import (
	"context"

	"github.com/coder/coder/v2/codersdk"
)

type Fetcher interface {
	Fetch(ctx context.Context) (codersdk.AppearanceConfig, error)
}

type AGPLFetcher struct {
	docsURL        string
	hidePrerelease bool
}

func (f AGPLFetcher) Fetch(context.Context) (codersdk.AppearanceConfig, error) {
	return codersdk.AppearanceConfig{
		AnnouncementBanners: []codersdk.BannerConfig{},
		SupportLinks:        codersdk.DefaultSupportLinks(f.docsURL),
		DocsURL:             f.docsURL,
		HidePrerelease:      f.hidePrerelease,
	}, nil
}

func NewDefaultFetcher(docsURL string, hidePrerelease bool) Fetcher {
	if docsURL == "" {
		docsURL = codersdk.DefaultDocsURL()
	}
	return &AGPLFetcher{
		docsURL:        docsURL,
		hidePrerelease: hidePrerelease,
	}
}
