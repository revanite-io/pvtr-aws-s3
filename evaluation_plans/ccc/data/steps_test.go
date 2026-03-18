package data

import (
	"testing"

	"github.com/gemaraproj/go-gemara"

	d "github.com/revanite-io/pvtr-aws-s3/data"
)

// ptr is a generic helper for creating pointer values in test data.
func ptr[T any](v T) *T {
	return &v
}

// --- KMSEncryptionConfigured ---

func TestKMSEncryptionConfigured(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name: "SSE-KMS with CMK returns Passed",
			payload: d.Payload{
				Encryption: &d.EncryptionData{
					SSEAlgorithm:   ptr("aws:kms"),
					KMSMasterKeyID: ptr("arn:aws:kms:us-east-1:123456789012:key/test-key"),
				},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "SSE-KMS-DSSE with CMK returns Passed",
			payload: d.Payload{
				Encryption: &d.EncryptionData{
					SSEAlgorithm:   ptr("aws:kms:dsse"),
					KMSMasterKeyID: ptr("arn:aws:kms:us-east-1:123456789012:key/test-key"),
				},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "AES256 returns Failed",
			payload: d.Payload{
				Encryption: &d.EncryptionData{
					SSEAlgorithm: ptr("AES256"),
				},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "SSE-KMS without key ID returns Failed",
			payload: d.Payload{
				Encryption: &d.EncryptionData{
					SSEAlgorithm: ptr("aws:kms"),
				},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "nil Encryption returns Unknown",
			payload: d.Payload{},
			wantResult: gemara.Unknown,
		},
		{
			name:       "wrong type returns Unknown",
			payload:    "not a payload",
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := KMSEncryptionConfigured(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- BucketPolicyDeniesUntrustedKMSKeys ---

func TestBucketPolicyDeniesUntrustedKMSKeys(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name: "has KMS restriction returns Passed",
			payload: d.Payload{
				BucketPolicy: &d.BucketPolicyData{HasKMSKeyRestriction: true},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "no KMS restriction returns Failed",
			payload: d.Payload{
				BucketPolicy: &d.BucketPolicyData{HasKMSKeyRestriction: false},
			},
			wantResult: gemara.Failed,
		},
		{
			name:       "nil BucketPolicy returns Unknown",
			payload:    d.Payload{},
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := BucketPolicyDeniesUntrustedKMSKeys(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- PreventUntrustedKmsKeysForBucketRead ---

func TestPreventUntrustedKmsKeysForBucketRead(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name: "KMS with policy restriction returns Passed",
			payload: d.Payload{
				Encryption:   &d.EncryptionData{SSEAlgorithm: ptr("aws:kms")},
				BucketPolicy: &d.BucketPolicyData{HasKMSKeyRestriction: true},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "KMS without policy restriction returns NeedsReview",
			payload: d.Payload{
				Encryption:   &d.EncryptionData{SSEAlgorithm: ptr("aws:kms")},
				BucketPolicy: &d.BucketPolicyData{HasKMSKeyRestriction: false},
			},
			wantResult: gemara.NeedsReview,
		},
		{
			name: "AES256 returns Failed",
			payload: d.Payload{
				Encryption: &d.EncryptionData{SSEAlgorithm: ptr("AES256")},
			},
			wantResult: gemara.Failed,
		},
		{
			name:       "nil Encryption returns Unknown",
			payload:    d.Payload{},
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := PreventUntrustedKmsKeysForBucketRead(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- PreventUntrustedKmsKeysForBucketWrite ---

func TestPreventUntrustedKmsKeysForBucketWrite(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name: "KMS with policy restriction returns Passed",
			payload: d.Payload{
				Encryption:   &d.EncryptionData{SSEAlgorithm: ptr("aws:kms")},
				BucketPolicy: &d.BucketPolicyData{HasKMSKeyRestriction: true},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "KMS without policy restriction returns Failed",
			payload: d.Payload{
				Encryption:   &d.EncryptionData{SSEAlgorithm: ptr("aws:kms")},
				BucketPolicy: &d.BucketPolicyData{HasKMSKeyRestriction: false},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "AES256 returns Failed",
			payload: d.Payload{
				Encryption: &d.EncryptionData{SSEAlgorithm: ptr("AES256")},
			},
			wantResult: gemara.Failed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := PreventUntrustedKmsKeysForBucketWrite(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- PublicAccessBlockEnabled ---

func TestPublicAccessBlockEnabled(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name: "all settings enabled returns Passed",
			payload: d.Payload{
				PublicAccessBlock: &d.PublicAccessBlockData{
					BlockPublicAcls:       ptr(true),
					BlockPublicPolicy:     ptr(true),
					IgnorePublicAcls:      ptr(true),
					RestrictPublicBuckets: ptr(true),
				},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "BlockPublicAcls disabled returns Failed",
			payload: d.Payload{
				PublicAccessBlock: &d.PublicAccessBlockData{
					BlockPublicAcls:       ptr(false),
					BlockPublicPolicy:     ptr(true),
					IgnorePublicAcls:      ptr(true),
					RestrictPublicBuckets: ptr(true),
				},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "IgnorePublicAcls disabled returns Failed",
			payload: d.Payload{
				PublicAccessBlock: &d.PublicAccessBlockData{
					BlockPublicAcls:       ptr(true),
					BlockPublicPolicy:     ptr(true),
					IgnorePublicAcls:      ptr(false),
					RestrictPublicBuckets: ptr(true),
				},
			},
			wantResult: gemara.Failed,
		},
		{
			name:       "nil PublicAccessBlock returns Unknown",
			payload:    d.Payload{},
			wantResult: gemara.Unknown,
		},
		{
			name:       "wrong type returns Unknown",
			payload:    "not a payload",
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := PublicAccessBlockEnabled(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- ObjectLockEnabled ---

func TestObjectLockEnabled(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name: "enabled with versioning returns Passed",
			payload: d.Payload{
				ObjectLock: &d.ObjectLockData{Enabled: ptr(true)},
				Versioning: &d.VersioningData{Status: ptr("Enabled")},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "enabled without versioning returns Failed",
			payload: d.Payload{
				ObjectLock: &d.ObjectLockData{Enabled: ptr(true)},
				Versioning: &d.VersioningData{Status: ptr("Suspended")},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "disabled returns Failed",
			payload: d.Payload{
				ObjectLock: &d.ObjectLockData{Enabled: ptr(false)},
			},
			wantResult: gemara.Failed,
		},
		{
			name:       "nil ObjectLock returns Unknown",
			payload:    d.Payload{},
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := ObjectLockEnabled(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- RetentionPolicyLocked ---

func TestRetentionPolicyLocked(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name: "COMPLIANCE mode returns Passed",
			payload: d.Payload{
				ObjectLock: &d.ObjectLockData{
					Enabled:          ptr(true),
					DefaultRetention: &d.RetentionData{Mode: ptr("COMPLIANCE")},
				},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "GOVERNANCE mode returns Failed",
			payload: d.Payload{
				ObjectLock: &d.ObjectLockData{
					Enabled:          ptr(true),
					DefaultRetention: &d.RetentionData{Mode: ptr("GOVERNANCE")},
				},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "Object Lock disabled returns Failed",
			payload: d.Payload{
				ObjectLock: &d.ObjectLockData{Enabled: ptr(false)},
			},
			wantResult: gemara.Failed,
		},
		{
			name:       "nil ObjectLock returns Unknown",
			payload:    d.Payload{},
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := RetentionPolicyLocked(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- DefaultRetentionConfigured ---

func TestDefaultRetentionConfigured(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name: "configured with days returns Passed",
			payload: d.Payload{
				ObjectLock: &d.ObjectLockData{
					Enabled: ptr(true),
					DefaultRetention: &d.RetentionData{
						Mode: ptr("COMPLIANCE"),
						Days: ptr(int32(1)),
					},
				},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "configured with years returns Passed",
			payload: d.Payload{
				ObjectLock: &d.ObjectLockData{
					Enabled: ptr(true),
					DefaultRetention: &d.RetentionData{
						Mode:  ptr("COMPLIANCE"),
						Years: ptr(int32(1)),
					},
				},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "no retention period returns Failed",
			payload: d.Payload{
				ObjectLock: &d.ObjectLockData{
					Enabled:          ptr(true),
					DefaultRetention: &d.RetentionData{Mode: ptr("COMPLIANCE")},
				},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "Object Lock disabled returns Failed",
			payload: d.Payload{
				ObjectLock: &d.ObjectLockData{Enabled: ptr(false)},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "no default retention returns Failed",
			payload: d.Payload{
				ObjectLock: &d.ObjectLockData{Enabled: ptr(true)},
			},
			wantResult: gemara.Failed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := DefaultRetentionConfigured(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- DeletionPreventedByRetention ---

func TestDeletionPreventedByRetention(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name: "COMPLIANCE mode returns Passed",
			payload: d.Payload{
				ObjectLock: &d.ObjectLockData{
					Enabled:          ptr(true),
					DefaultRetention: &d.RetentionData{Mode: ptr("COMPLIANCE")},
				},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "GOVERNANCE mode returns NeedsReview",
			payload: d.Payload{
				ObjectLock: &d.ObjectLockData{
					Enabled:          ptr(true),
					DefaultRetention: &d.RetentionData{Mode: ptr("GOVERNANCE")},
				},
			},
			wantResult: gemara.NeedsReview,
		},
		{
			name: "Object Lock disabled returns Failed",
			payload: d.Payload{
				ObjectLock: &d.ObjectLockData{Enabled: ptr(false)},
			},
			wantResult: gemara.Failed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := DeletionPreventedByRetention(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- VersioningEnabled ---

func TestVersioningEnabled(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name: "enabled returns Passed",
			payload: d.Payload{
				Versioning: &d.VersioningData{Status: ptr("Enabled")},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "suspended returns Failed",
			payload: d.Payload{
				Versioning: &d.VersioningData{Status: ptr("Suspended")},
			},
			wantResult: gemara.Failed,
		},
		{
			name:       "nil Versioning returns Unknown",
			payload:    d.Payload{},
			wantResult: gemara.Unknown,
		},
		{
			name:       "wrong type returns Unknown",
			payload:    "not a payload",
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := VersioningEnabled(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- NewVersionOnModification ---

func TestNewVersionOnModification(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name: "versioning enabled returns NeedsReview",
			payload: d.Payload{
				Versioning: &d.VersioningData{Status: ptr("Enabled")},
			},
			wantResult: gemara.NeedsReview,
		},
		{
			name: "versioning disabled returns Failed",
			payload: d.Payload{
				Versioning: &d.VersioningData{Status: ptr("Suspended")},
			},
			wantResult: gemara.Failed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := NewVersionOnModification(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- AccessLoggingConfigured ---

func TestAccessLoggingConfigured(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name: "S3 logging enabled returns Passed",
			payload: d.Payload{
				Logging: &d.LoggingData{
					Enabled:      true,
					TargetBucket: ptr("my-log-bucket"),
				},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "CloudTrail enabled returns Passed",
			payload: d.Payload{
				CloudTrail: &d.CloudTrailData{DataEventsLogged: true},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "both enabled returns Passed",
			payload: d.Payload{
				Logging: &d.LoggingData{
					Enabled:      true,
					TargetBucket: ptr("my-log-bucket"),
				},
				CloudTrail: &d.CloudTrailData{DataEventsLogged: true},
			},
			wantResult: gemara.Passed,
		},
		{
			name:       "neither enabled returns Failed",
			payload:    d.Payload{},
			wantResult: gemara.Failed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := AccessLoggingConfigured(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- LogBucketHighestSensitivity ---

func TestLogBucketHighestSensitivity(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name: "log bucket tagged high returns Passed",
			payload: d.Payload{
				Logging: &d.LoggingData{
					Enabled:       true,
					LogBucketTags: map[string]string{"sensitivity": "high"},
				},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "log bucket tagged low returns Failed",
			payload: d.Payload{
				Logging: &d.LoggingData{
					Enabled:       true,
					LogBucketTags: map[string]string{"sensitivity": "low"},
				},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "log bucket no sensitivity tag returns Failed",
			payload: d.Payload{
				Logging: &d.LoggingData{
					Enabled:       true,
					LogBucketTags: map[string]string{"other": "tag"},
				},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "no tags available returns NeedsReview",
			payload: d.Payload{
				Logging: &d.LoggingData{Enabled: true},
			},
			wantResult: gemara.NeedsReview,
		},
		{
			name:       "no logging returns NeedsReview",
			payload:    d.Payload{},
			wantResult: gemara.NeedsReview,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := LogBucketHighestSensitivity(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- MfaDeleteSupported ---

func TestMfaDeleteSupported(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name:       "valid payload returns Passed",
			payload:    d.Payload{},
			wantResult: gemara.Passed,
		},
		{
			name:       "wrong type returns Unknown",
			payload:    "not a payload",
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := MfaDeleteSupported(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- MfaDeleteEnforced ---

func TestMfaDeleteEnforced(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name: "MFA Delete enabled returns Passed",
			payload: d.Payload{
				Versioning: &d.VersioningData{MFADelete: ptr("Enabled")},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "MFA Delete disabled returns Failed",
			payload: d.Payload{
				Versioning: &d.VersioningData{MFADelete: ptr("Disabled")},
			},
			wantResult: gemara.Failed,
		},
		{
			name:       "nil Versioning returns Unknown",
			payload:    d.Payload{},
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := MfaDeleteEnforced(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- MfaDeletionLogged ---

func TestMfaDeletionLogged(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name: "CloudTrail data events enabled returns Passed",
			payload: d.Payload{
				CloudTrail: &d.CloudTrailData{DataEventsLogged: true},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "CloudTrail not configured returns Failed",
			payload: d.Payload{
				CloudTrail: &d.CloudTrailData{DataEventsLogged: false},
			},
			wantResult: gemara.Failed,
		},
		{
			name:       "nil CloudTrail returns Failed",
			payload:    d.Payload{},
			wantResult: gemara.Failed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := MfaDeletionLogged(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- BucketPolicyEnforcesSSL ---

func TestBucketPolicyEnforcesSSL(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name: "SSL policy present returns Passed",
			payload: d.Payload{
				BucketPolicy: &d.BucketPolicyData{HasSSLOnlyPolicy: true},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "no SSL policy returns Failed",
			payload: d.Payload{
				BucketPolicy: &d.BucketPolicyData{HasSSLOnlyPolicy: false},
			},
			wantResult: gemara.Failed,
		},
		{
			name:       "nil BucketPolicy returns Unknown",
			payload:    d.Payload{},
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := BucketPolicyEnforcesSSL(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}
