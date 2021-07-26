package image

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"sync"

	"github.com/google/go-containerregistry/pkg/v1"
	"golang.org/x/sync/semaphore"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/artifact"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/config/scanner"
	"github.com/aquasecurity/fanal/image"
	"github.com/aquasecurity/fanal/log"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/walker"
)

const (
	parallel = 5
)

type Artifact struct {
	image               image.Image
	cache               cache.ArtifactCache
	analyzer            analyzer.Analyzer
	scanner             scanner.Scanner
	configScannerOption config.ScannerOption
}

func NewArtifact(img image.Image, c cache.ArtifactCache, disabled []analyzer.Type, opt config.ScannerOption) (artifact.Artifact, error) {
	// Register config analyzers
	if err := config.RegisterConfigAnalyzers(opt.FilePatterns); err != nil {
		return nil, xerrors.Errorf("config scanner error: %w", err)
	}

	s, err := scanner.New("", opt.Namespaces, opt.PolicyPaths, opt.DataPaths, opt.Trace)
	if err != nil {
		return nil, xerrors.Errorf("scanner error: %w", err)
	}

	// Do not scan go.sum in container images, only scan go binaries
	disabled = append(disabled, analyzer.TypeGoMod)

	return Artifact{
		image:               img,
		cache:               c,
		analyzer:            analyzer.NewAnalyzer(disabled),
		scanner:             s,
		configScannerOption: opt,
	}, nil
}

func (a Artifact) Inspect(ctx context.Context) (types.ArtifactReference, error) {
	imageID, err := a.image.ID()
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("unable to get the image ID: %w", err)
	}

	diffIDs, err := a.image.LayerIDs()
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("unable to get layer IDs: %w", err)
	}

	// Debug
	log.Logger.Debugf("Image ID: %s", imageID)
	log.Logger.Debugf("Diff IDs: %v", diffIDs)

	// Convert image ID and layer IDs to cache keys
	imageKey, layerKeys, layerKeyMap, err := a.calcCacheKeys(imageID, diffIDs)
	if err != nil {
		return types.ArtifactReference{}, err
	}

	missingImage, missingLayers, err := a.cache.MissingBlobs(imageKey, layerKeys)
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("unable to get missing layers: %w", err)
	}

	missingImageKey := imageKey
	if missingImage {
		log.Logger.Debugf("Missing image ID: %s", imageID)
	} else {
		missingImageKey = ""
	}

	artifactInfo, layerHistoryMap, err := a.getArtifactConfig(imageID, diffIDs)
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("unable to analyze config: %w", err)
	}

	osFound, err := a.inspect(ctx, missingImageKey, missingLayers, layerKeyMap, layerHistoryMap)
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("analyze error: %w", err)
	}

	if missingImageKey != "" {
		log.Logger.Debugf("Missing image cache: %s", missingImageKey)
		if err := a.saveArtifact(missingImageKey, artifactInfo, osFound); err != nil {
			return types.ArtifactReference{}, xerrors.Errorf("unable to save artifact: %w", err)
		}
	}

	return types.ArtifactReference{
		Name:        a.image.Name(),
		Type:        types.ArtifactContainerImage,
		ID:          imageKey,
		BlobIDs:     layerKeys,
		RepoTags:    a.image.RepoTags(),
		RepoDigests: a.image.RepoDigests(),
	}, nil
}

func (a Artifact) calcCacheKeys(imageID string, diffIDs []string) (string, []string, map[string]string, error) {
	// Pass an empty config scanner option so that the cache key can be the same, even when policies are updated.
	imageKey, err := cache.CalcKey(imageID, a.analyzer.ImageConfigAnalyzerVersions(), &config.ScannerOption{})
	if err != nil {
		return "", nil, nil, err
	}

	layerKeyMap := map[string]string{}
	var layerKeys []string
	for _, diffID := range diffIDs {
		blobKey, err := cache.CalcKey(diffID, a.analyzer.AnalyzerVersions(), &a.configScannerOption)
		if err != nil {
			return "", nil, nil, err
		}
		layerKeys = append(layerKeys, blobKey)
		layerKeyMap[blobKey] = diffID
	}
	return imageKey, layerKeys, layerKeyMap, nil
}

func (a Artifact) inspect(ctx context.Context, missingImageKey string, layerKeys []string, layerKeyMap map[string]string,
	historyLayerMap map[string]types.LayerHistory) (types.OS, error) {

	done := make(chan struct{})
	errCh := make(chan error)

	var osFound types.OS
	for _, k := range layerKeys {
		go func(ctx context.Context, layerKey string) {
			diffID := layerKeyMap[layerKey]
			layerInfo, err := a.inspectLayer(ctx, diffID)
			if err != nil {
				errCh <- xerrors.Errorf("failed to analyze layer: %s : %w", diffID, err)
				return
			}
			layerInfo.LayerHistory = historyLayerMap[diffID]
			if err = a.cache.PutBlob(layerKey, layerInfo); err != nil {
				errCh <- xerrors.Errorf("failed to store layer: %s in cache: %w", layerKey, err)
				return
			}
			if layerInfo.OS != nil {
				osFound = *layerInfo.OS
			}
			done <- struct{}{}
		}(ctx, k)
	}

	for range layerKeys {
		select {
		case <-done:
		case err := <-errCh:
			return osFound, err
		case <-ctx.Done():
			return osFound, xerrors.Errorf("timeout: %w", ctx.Err())
		}
	}
	return osFound, nil
}

func (a Artifact) inspectLayer(ctx context.Context, diffID string) (types.BlobInfo, error) {
	log.Logger.Debugf("Missing diff ID: %s", diffID)

	layerDigest, r, err := a.uncompressedLayer(diffID)
	if err != nil {
		return types.BlobInfo{}, xerrors.Errorf("unable to get uncompressed layer %s: %w", diffID, err)
	}

	var wg sync.WaitGroup
	result := new(analyzer.AnalysisResult)
	limit := semaphore.NewWeighted(parallel)

	opqDirs, whFiles, layerSize, err := walker.WalkLayerTar(r, func(filePath string, info os.FileInfo, opener analyzer.Opener) error {
		if err = a.analyzer.AnalyzeFile(ctx, &wg, limit, result, "", filePath, info, opener); err != nil {
			return xerrors.Errorf("failed to analyze %s: %w", filePath, err)
		}
		return nil
	})
	if err != nil {
		return types.BlobInfo{}, xerrors.Errorf("walk error: %w", err)
	}

	// Wait for all the goroutine to finish.
	wg.Wait()

	// Sort the analysis result for consistent results
	result.Sort()

	layerInfo := types.BlobInfo{
		SchemaVersion: types.BlobJSONSchemaVersion,
		Digest:        layerDigest,
		DiffID:        diffID,
		OS:            result.OS,
		PackageInfos:  result.PackageInfos,
		Applications:  result.Applications,
		OpaqueDirs:    opqDirs,
		WhiteoutFiles: whFiles,
		Size:          layerSize,
	}
	return layerInfo, nil
}

func (a Artifact) uncompressedLayer(diffID string) (string, io.Reader, error) {
	// diffID is a hash of the uncompressed layer
	h, err := v1.NewHash(diffID)
	if err != nil {
		return "", nil, xerrors.Errorf("invalid layer ID (%s): %w", diffID, err)
	}

	layer, err := a.image.LayerByDiffID(h)
	if err != nil {
		return "", nil, xerrors.Errorf("failed to get the layer (%s): %w", diffID, err)
	}

	// digest is a hash of the compressed layer
	var digest string
	if a.isCompressed(layer) {
		d, err := layer.Digest()
		if err != nil {
			return "", nil, xerrors.Errorf("failed to get the digest (%s): %w", diffID, err)
		}
		digest = d.String()
	}

	r, err := layer.Uncompressed()
	if err != nil {
		return "", nil, xerrors.Errorf("failed to get the layer content (%s): %w", diffID, err)
	}
	return digest, r, nil
}

// ref. https://github.com/google/go-containerregistry/issues/701
func (a Artifact) isCompressed(l v1.Layer) bool {
	_, uncompressed := reflect.TypeOf(l).Elem().FieldByName("UncompressedLayer")
	return !uncompressed
}

func (a Artifact) saveArtifact(imageID string, info types.ArtifactInfo, osFound types.OS) error {
	configBlob, err := a.image.ConfigBlob()
	if err != nil {
		return xerrors.Errorf("unable to get config blob: %w", err)
	}
	info.HistoryPackages = a.analyzer.AnalyzeImageConfig(osFound, configBlob)
	if err := a.cache.PutArtifact(imageID, info); err != nil {
		return xerrors.Errorf("failed to put image info into the cache: %w", err)
	}
	return nil
}

func (a Artifact) getArtifactConfig(imageID string, layerDiffs []string) (info types.ArtifactInfo, historyLayerMap map[string]types.LayerHistory, err error) {
	configBlob, err := a.image.ConfigBlob()
	if err != nil {
		return info, nil, xerrors.Errorf("unable to get config blob: %w", err)
	}

	var s1 v1.ConfigFile
	if err := json.Unmarshal(configBlob, &s1); err != nil {
		return info, nil, xerrors.Errorf("json marshal error: %w", err)
	}

	info = types.ArtifactInfo{
		SchemaVersion: types.ArtifactJSONSchemaVersion,
		Architecture:  s1.Architecture,
		Created:       s1.Created.Time,
		DockerVersion: s1.DockerVersion,
		OS:            s1.OS,
		Author:        s1.Author,
		ImageId:       imageID,
		Environment:   s1.Config.Env,
		Labels:        s1.Config.Labels,
	}
	// Indecies should match. Dont consider empty layers for now
	historyLayerMap = make(map[string]types.LayerHistory)
	var layerDiffId string
	histIndex := 0
	for _, configHistory := range s1.History {
		if !configHistory.EmptyLayer {
			layerDiffId = layerDiffs[histIndex]
			historyLayerMap[layerDiffId] = types.LayerHistory{
				Author:    configHistory.Author,
				Created:   configHistory.Created.Time,
				CreatedBy: configHistory.CreatedBy,
				Comment:   configHistory.Comment,
			}
			histIndex++
		}
	}
	return info, historyLayerMap, nil
}
