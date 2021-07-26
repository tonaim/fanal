package applier

import (
	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/types"
	"golang.org/x/xerrors"
)

type Applier struct {
	cache cache.LocalArtifactCache
}

func NewApplier(c cache.LocalArtifactCache) Applier {
	return Applier{cache: c}
}

func (a Applier) ApplyLayers(imageID string, diffIDs []string) (types.ArtifactDetail, error) {
	var layers []types.BlobInfo
	var layerMetadata []types.LayerMetadata
	for _, diffID := range diffIDs {
		layer, _ := a.cache.GetBlob(diffID)
		if layer.SchemaVersion == 0 {
			return types.ArtifactDetail{}, xerrors.Errorf("layer cache missing: %s", diffID)
		}
		layers = append(layers, layer)
		layerMetadata = append(layerMetadata, types.LayerMetadata{
			LayerDigest:  layer.Digest,
			Size:         layer.Size,
			LayerHistory: layer.LayerHistory,
		})
	}

	mergedLayer := ApplyLayers(layers)
	if mergedLayer.OS == nil {
		return mergedLayer, analyzer.ErrUnknownOS // send back package and apps info regardless
	} else if mergedLayer.Packages == nil {
		return mergedLayer, analyzer.ErrNoPkgsDetected // send back package and apps info regardless
	}

	imageInfo, _ := a.cache.GetArtifact(imageID)
	mergedLayer.HistoryPackages = imageInfo.HistoryPackages
	// Artifact Metadata details
	mergedLayer.LayerMetadata = layerMetadata
	mergedLayer.Created = imageInfo.Created
	mergedLayer.DockerVersion = imageInfo.DockerVersion
	mergedLayer.Architecture = imageInfo.Architecture
	mergedLayer.ImageId = imageInfo.ImageId
	mergedLayer.Environment = imageInfo.Environment
	mergedLayer.Author = imageInfo.Author
	mergedLayer.Labels = imageInfo.Labels
	return mergedLayer, nil
}
