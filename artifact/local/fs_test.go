package local

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
	_ "github.com/aquasecurity/fanal/analyzer/all"
	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/types"
)

func TestArtifact_Inspect(t *testing.T) {
	type fields struct {
		dir string
	}
	tests := []struct {
		name               string
		fields             fields
		scannerOpt         config.ScannerOption
		disabledAnalyzers  []analyzer.Type
		putBlobExpectation cache.ArtifactCachePutBlobExpectation
		want               types.ArtifactReference
		wantErr            string
	}{
		{
			name: "happy path",
			fields: fields{
				dir: "./testdata",
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobID: "sha256:b2c1176706c4ef61e9d73fa66be737fdd839be81e4e5a0a9f7678d712c5f760c",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						DiffID:        "sha256:fe942ab361ebde7ea90ba16cfb08c4c03c29bbb5253467f8809af0d63185bbd4",
						OS: &types.OS{
							Family: "alpine",
							Name:   "3.11.6",
						},
						PackageInfos: []types.PackageInfo{
							{
								FilePath: "lib/apk/db/installed",
								Packages: []types.Package{
									{Name: "musl", Version: "1.1.24-r2", SrcName: "musl", SrcVersion: "1.1.24-r2"},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "host",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:b2c1176706c4ef61e9d73fa66be737fdd839be81e4e5a0a9f7678d712c5f760c",
				BlobIDs: []string{
					"sha256:b2c1176706c4ef61e9d73fa66be737fdd839be81e4e5a0a9f7678d712c5f760c",
				},
			},
		},
		{
			name: "disable analyzers",
			fields: fields{
				dir: "./testdata",
			},
			disabledAnalyzers: []analyzer.Type{analyzer.TypeAlpine, analyzer.TypeApk},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobID: "sha256:47b8720b43faaf3a5a3cd0228a5c79e9998db135b366a0ddd6f8a79504b18dc0",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						DiffID:        "sha256:5e55b099509fb48929874b3d2952d8949f82c34afde6bdf4dfc70765bb32b74f",
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "host",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:47b8720b43faaf3a5a3cd0228a5c79e9998db135b366a0ddd6f8a79504b18dc0",
				BlobIDs: []string{
					"sha256:47b8720b43faaf3a5a3cd0228a5c79e9998db135b366a0ddd6f8a79504b18dc0",
				},
			},
		},
		{
			name: "sad path PutBlob returns an error",
			fields: fields{
				dir: "./testdata",
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobID: "sha256:b2c1176706c4ef61e9d73fa66be737fdd839be81e4e5a0a9f7678d712c5f760c",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						DiffID:        "sha256:fe942ab361ebde7ea90ba16cfb08c4c03c29bbb5253467f8809af0d63185bbd4",
						OS: &types.OS{
							Family: "alpine",
							Name:   "3.11.6",
						},
						PackageInfos: []types.PackageInfo{
							{
								FilePath: "lib/apk/db/installed",
								Packages: []types.Package{
									{Name: "musl", Version: "1.1.24-r2", SrcName: "musl", SrcVersion: "1.1.24-r2"},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{
					Err: errors.New("error"),
				},
			},
			wantErr: "failed to store blob",
		},
		{
			name: "sad path with no such directory",
			fields: fields{
				dir: "./testdata/unknown",
			},
			wantErr: "no such file or directory",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := new(cache.MockArtifactCache)
			c.ApplyPutBlobExpectation(tt.putBlobExpectation)

			a, err := NewArtifact(tt.fields.dir, c, tt.disabledAnalyzers, tt.scannerOpt)
			require.NoError(t, err)

			got, err := a.Inspect(context.Background())
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
