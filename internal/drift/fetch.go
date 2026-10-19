package drift

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// MaxSchema is the largest schema HTTPFetcher downloads.
const MaxSchema = 100 << 20

// HTTPFetcher downloads schemas over HTTPS, caching each URL for the run.
func HTTPFetcher() Fetcher {
	client := &http.Client{Timeout: 3 * time.Minute}
	cache := map[string][]byte{}
	return func(ctx context.Context, url string) ([]byte, error) {
		if b, ok := cache[url]; ok {
			return b, nil
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "opfence-catalog-check")
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("HTTP %s", resp.Status)
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, MaxSchema+1))
		if err != nil {
			return nil, err
		}
		if len(b) > MaxSchema {
			return nil, fmt.Errorf("larger than %d MiB", MaxSchema>>20)
		}
		cache[url] = b
		return b, nil
	}
}
