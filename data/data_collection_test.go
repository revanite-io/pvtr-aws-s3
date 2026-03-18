package data

import (
	"errors"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cloudtrailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/privateerproj/privateer-sdk/config"
)

func testConfig(bucketName string) *config.Config {
	return &config.Config{
		Vars: map[string]interface{}{
			"bucketname": bucketName,
		},
	}
}

// --- LoadWithOptions ---

func TestLoadWithOptions_MissingBucketName(t *testing.T) {
	cfg := &config.Config{Vars: map[string]interface{}{}}
	_, err := LoadWithOptions(cfg, allMockOptions()...)
	if err == nil {
		t.Fatal("expected error for missing bucketname")
	}
}

func TestLoadWithOptions_MinimalSuccess(t *testing.T) {
	result, err := LoadWithOptions(testConfig("my-bucket"), allMockOptions()...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	payload, ok := result.(Payload)
	if !ok {
		t.Fatalf("expected Payload, got %T", result)
	}

	if payload.BucketName != "my-bucket" {
		t.Errorf("BucketName = %q, want %q", payload.BucketName, "my-bucket")
	}

	if payload.Region != "us-east-2" {
		t.Errorf("Region = %q, want %q", payload.Region, "us-east-2")
	}
}

func TestLoadWithOptions_LocationError(t *testing.T) {
	opts := []Option{
		WithS3Client(&mockS3Client{
			locationErr: errors.New("access denied"),
		}),
		WithCloudTrailClient(&mockCloudTrailClient{}),
	}
	_, err := LoadWithOptions(testConfig("my-bucket"), opts...)
	if err == nil {
		t.Fatal("expected error when location fetch fails")
	}
}

func TestLoadWithOptions_EmptyLocationIsUsEast1(t *testing.T) {
	opts := []Option{
		WithS3Client(&mockS3Client{
			locationResp: &s3.GetBucketLocationOutput{
				LocationConstraint: "",
			},
		}),
		WithCloudTrailClient(&mockCloudTrailClient{}),
	}
	result, err := LoadWithOptions(testConfig("my-bucket"), opts...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	payload := result.(Payload)
	if payload.Region != "us-east-1" {
		t.Errorf("Region = %q, want %q", payload.Region, "us-east-1")
	}
}

// --- fetchVersioning ---

func TestLoadWithOptions_Versioning(t *testing.T) {
	opts := []Option{
		WithS3Client(&mockS3Client{
			versioningResp: &s3.GetBucketVersioningOutput{
				Status:    s3types.BucketVersioningStatusEnabled,
				MFADelete: s3types.MFADeleteStatusEnabled,
			},
		}),
		WithCloudTrailClient(&mockCloudTrailClient{}),
	}
	result, err := LoadWithOptions(testConfig("my-bucket"), opts...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	payload := result.(Payload)

	if payload.Versioning == nil {
		t.Fatal("Versioning is nil")
	}
	if payload.Versioning.Status == nil || *payload.Versioning.Status != "Enabled" {
		t.Errorf("Status = %v, want Enabled", payload.Versioning.Status)
	}
	if payload.Versioning.MFADelete == nil || *payload.Versioning.MFADelete != "Enabled" {
		t.Errorf("MFADelete = %v, want Enabled", payload.Versioning.MFADelete)
	}
}

func TestLoadWithOptions_VersioningError(t *testing.T) {
	opts := []Option{
		WithS3Client(&mockS3Client{
			versioningErr: errors.New("fail"),
		}),
		WithCloudTrailClient(&mockCloudTrailClient{}),
	}
	result, err := LoadWithOptions(testConfig("my-bucket"), opts...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	payload := result.(Payload)
	if payload.Versioning != nil {
		t.Error("expected nil Versioning on error")
	}
}

// --- fetchEncryption ---

func TestLoadWithOptions_Encryption(t *testing.T) {
	kmsKeyID := "arn:aws:kms:us-east-1:123456789012:key/test-key"
	bke := true
	opts := []Option{
		WithS3Client(&mockS3Client{
			encryptionResp: &s3.GetBucketEncryptionOutput{
				ServerSideEncryptionConfiguration: &s3types.ServerSideEncryptionConfiguration{
					Rules: []s3types.ServerSideEncryptionRule{
						{
							ApplyServerSideEncryptionByDefault: &s3types.ServerSideEncryptionByDefault{
								SSEAlgorithm:   s3types.ServerSideEncryptionAwsKms,
								KMSMasterKeyID: &kmsKeyID,
							},
							BucketKeyEnabled: &bke,
						},
					},
				},
			},
		}),
		WithCloudTrailClient(&mockCloudTrailClient{}),
	}
	result, err := LoadWithOptions(testConfig("my-bucket"), opts...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	payload := result.(Payload)

	if payload.Encryption == nil {
		t.Fatal("Encryption is nil")
	}
	if payload.Encryption.SSEAlgorithm == nil || *payload.Encryption.SSEAlgorithm != "aws:kms" {
		t.Errorf("SSEAlgorithm = %v, want aws:kms", payload.Encryption.SSEAlgorithm)
	}
	if payload.Encryption.KMSMasterKeyID == nil || *payload.Encryption.KMSMasterKeyID != kmsKeyID {
		t.Errorf("KMSMasterKeyID = %v, want %s", payload.Encryption.KMSMasterKeyID, kmsKeyID)
	}
	if payload.Encryption.BucketKeyEnabled == nil || !*payload.Encryption.BucketKeyEnabled {
		t.Error("BucketKeyEnabled should be true")
	}
}

func TestLoadWithOptions_EncryptionNoRules(t *testing.T) {
	opts := []Option{
		WithS3Client(&mockS3Client{
			encryptionResp: &s3.GetBucketEncryptionOutput{
				ServerSideEncryptionConfiguration: &s3types.ServerSideEncryptionConfiguration{
					Rules: []s3types.ServerSideEncryptionRule{},
				},
			},
		}),
		WithCloudTrailClient(&mockCloudTrailClient{}),
	}
	result, err := LoadWithOptions(testConfig("my-bucket"), opts...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	payload := result.(Payload)
	if payload.Encryption != nil {
		t.Error("expected nil Encryption when no rules")
	}
}

// --- fetchObjectLock ---

func TestLoadWithOptions_ObjectLock(t *testing.T) {
	days := ptr(int32(1))
	opts := []Option{
		WithS3Client(&mockS3Client{
			objectLockResp: &s3.GetObjectLockConfigurationOutput{
				ObjectLockConfiguration: &s3types.ObjectLockConfiguration{
					ObjectLockEnabled: s3types.ObjectLockEnabledEnabled,
					Rule: &s3types.ObjectLockRule{
						DefaultRetention: &s3types.DefaultRetention{
							Mode: s3types.ObjectLockRetentionModeCompliance,
							Days: days,
						},
					},
				},
			},
		}),
		WithCloudTrailClient(&mockCloudTrailClient{}),
	}
	result, err := LoadWithOptions(testConfig("my-bucket"), opts...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	payload := result.(Payload)

	if payload.ObjectLock == nil {
		t.Fatal("ObjectLock is nil")
	}
	if payload.ObjectLock.Enabled == nil || !*payload.ObjectLock.Enabled {
		t.Error("ObjectLock.Enabled should be true")
	}
	if payload.ObjectLock.DefaultRetention == nil {
		t.Fatal("DefaultRetention is nil")
	}
	if payload.ObjectLock.DefaultRetention.Mode == nil || *payload.ObjectLock.DefaultRetention.Mode != "COMPLIANCE" {
		t.Errorf("Mode = %v, want COMPLIANCE", payload.ObjectLock.DefaultRetention.Mode)
	}
	if payload.ObjectLock.DefaultRetention.Days == nil || *payload.ObjectLock.DefaultRetention.Days != 1 {
		t.Errorf("Days = %v, want 1", payload.ObjectLock.DefaultRetention.Days)
	}
}

// --- fetchPublicAccessBlock ---

func TestLoadWithOptions_PublicAccessBlock(t *testing.T) {
	opts := []Option{
		WithS3Client(&mockS3Client{
			publicAccessResp: &s3.GetPublicAccessBlockOutput{
				PublicAccessBlockConfiguration: &s3types.PublicAccessBlockConfiguration{
					BlockPublicAcls:       ptr(true),
					BlockPublicPolicy:     ptr(true),
					IgnorePublicAcls:      ptr(true),
					RestrictPublicBuckets: ptr(true),
				},
			},
		}),
		WithCloudTrailClient(&mockCloudTrailClient{}),
	}
	result, err := LoadWithOptions(testConfig("my-bucket"), opts...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	payload := result.(Payload)

	if payload.PublicAccessBlock == nil {
		t.Fatal("PublicAccessBlock is nil")
	}
	if payload.PublicAccessBlock.BlockPublicAcls == nil || !*payload.PublicAccessBlock.BlockPublicAcls {
		t.Error("BlockPublicAcls should be true")
	}
	if payload.PublicAccessBlock.RestrictPublicBuckets == nil || !*payload.PublicAccessBlock.RestrictPublicBuckets {
		t.Error("RestrictPublicBuckets should be true")
	}
}

// --- fetchLogging ---

func TestLoadWithOptions_Logging(t *testing.T) {
	logBucket := "my-log-bucket"
	prefix := "access-logs/"
	opts := []Option{
		WithS3Client(&mockS3Client{
			loggingResp: &s3.GetBucketLoggingOutput{
				LoggingEnabled: &s3types.LoggingEnabled{
					TargetBucket: &logBucket,
					TargetPrefix: &prefix,
				},
			},
			taggingResp: &s3.GetBucketTaggingOutput{
				TagSet: []s3types.Tag{
					{Key: ptr("sensitivity"), Value: ptr("high")},
					{Key: ptr("purpose"), Value: ptr("access-logs")},
				},
			},
		}),
		WithCloudTrailClient(&mockCloudTrailClient{}),
	}
	result, err := LoadWithOptions(testConfig("my-bucket"), opts...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	payload := result.(Payload)

	if payload.Logging == nil {
		t.Fatal("Logging is nil")
	}
	if !payload.Logging.Enabled {
		t.Error("Logging.Enabled should be true")
	}
	if payload.Logging.TargetBucket == nil || *payload.Logging.TargetBucket != logBucket {
		t.Errorf("TargetBucket = %v, want %s", payload.Logging.TargetBucket, logBucket)
	}
	if payload.Logging.LogBucketTags == nil {
		t.Fatal("LogBucketTags is nil")
	}
	if payload.Logging.LogBucketTags["sensitivity"] != "high" {
		t.Errorf("sensitivity tag = %q, want %q", payload.Logging.LogBucketTags["sensitivity"], "high")
	}
}

func TestLoadWithOptions_LoggingDisabled(t *testing.T) {
	result, err := LoadWithOptions(testConfig("my-bucket"), allMockOptions()...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	payload := result.(Payload)

	if payload.Logging == nil {
		t.Fatal("Logging is nil")
	}
	if payload.Logging.Enabled {
		t.Error("Logging.Enabled should be false when no logging configured")
	}
}

// --- fetchBucketPolicy ---

func TestLoadWithOptions_BucketPolicySSLAndKMS(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Sid": "DenyInsecureTransport",
				"Effect": "Deny",
				"Principal": "*",
				"Action": "s3:*",
				"Condition": {
					"Bool": {"aws:SecureTransport": "false"}
				}
			},
			{
				"Sid": "DenyUntrustedKMSKey",
				"Effect": "Deny",
				"Principal": "*",
				"Action": "s3:PutObject",
				"Condition": {
					"StringNotEqualsIfExists": {
						"s3:x-amz-server-side-encryption-aws-kms-key-id": "arn:aws:kms:us-east-1:123:key/abc"
					}
				}
			}
		]
	}`
	opts := []Option{
		WithS3Client(&mockS3Client{
			policyResp: &s3.GetBucketPolicyOutput{Policy: &policy},
		}),
		WithCloudTrailClient(&mockCloudTrailClient{}),
	}
	result, err := LoadWithOptions(testConfig("my-bucket"), opts...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	payload := result.(Payload)

	if payload.BucketPolicy == nil {
		t.Fatal("BucketPolicy is nil")
	}
	if !payload.BucketPolicy.HasSSLOnlyPolicy {
		t.Error("HasSSLOnlyPolicy should be true")
	}
	if !payload.BucketPolicy.HasKMSKeyRestriction {
		t.Error("HasKMSKeyRestriction should be true")
	}
}

func TestLoadWithOptions_BucketPolicyNoPolicy(t *testing.T) {
	opts := []Option{
		WithS3Client(&mockS3Client{
			policyErr: errors.New("NoSuchBucketPolicy"),
		}),
		WithCloudTrailClient(&mockCloudTrailClient{}),
	}
	result, err := LoadWithOptions(testConfig("my-bucket"), opts...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	payload := result.(Payload)
	if payload.BucketPolicy != nil {
		t.Error("expected nil BucketPolicy when no policy exists")
	}
}

func TestLoadWithOptions_BucketPolicyAllowOnly(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Sid": "AllowAccess",
				"Effect": "Allow",
				"Principal": "*",
				"Action": "s3:GetObject"
			}
		]
	}`
	opts := []Option{
		WithS3Client(&mockS3Client{
			policyResp: &s3.GetBucketPolicyOutput{Policy: &policy},
		}),
		WithCloudTrailClient(&mockCloudTrailClient{}),
	}
	result, err := LoadWithOptions(testConfig("my-bucket"), opts...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	payload := result.(Payload)

	if payload.BucketPolicy == nil {
		t.Fatal("BucketPolicy is nil")
	}
	if payload.BucketPolicy.HasSSLOnlyPolicy {
		t.Error("HasSSLOnlyPolicy should be false for Allow-only policy")
	}
	if payload.BucketPolicy.HasKMSKeyRestriction {
		t.Error("HasKMSKeyRestriction should be false for Allow-only policy")
	}
}

// --- fetchCloudTrail ---

func TestLoadWithOptions_CloudTrailClassicSelector(t *testing.T) {
	trailARN := "arn:aws:cloudtrail:us-east-1:123456789012:trail/my-trail"
	s3Type := "AWS::S3::Object"
	opts := []Option{
		WithS3Client(&mockS3Client{}),
		WithCloudTrailClient(&mockCloudTrailClient{
			describeResp: &cloudtrailOutput{
				TrailList: []cloudtrailtypes.Trail{
					{TrailARN: &trailARN},
				},
			},
			selectorsResp: &selectorsOutput{
				EventSelectors: []cloudtrailtypes.EventSelector{
					{
						DataResources: []cloudtrailtypes.DataResource{
							{
								Type:   &s3Type,
								Values: []string{fmt.Sprintf("arn:aws:s3:::%s/", "my-bucket")},
							},
						},
					},
				},
			},
		}),
	}
	result, err := LoadWithOptions(testConfig("my-bucket"), opts...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	payload := result.(Payload)

	if payload.CloudTrail == nil {
		t.Fatal("CloudTrail is nil")
	}
	if !payload.CloudTrail.DataEventsLogged {
		t.Error("DataEventsLogged should be true")
	}
	if payload.CloudTrail.TrailARN == nil || *payload.CloudTrail.TrailARN != trailARN {
		t.Errorf("TrailARN = %v, want %s", payload.CloudTrail.TrailARN, trailARN)
	}
}

func TestLoadWithOptions_CloudTrailNoTrails(t *testing.T) {
	result, err := LoadWithOptions(testConfig("my-bucket"), allMockOptions()...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	payload := result.(Payload)

	if payload.CloudTrail == nil {
		t.Fatal("CloudTrail is nil")
	}
	if payload.CloudTrail.DataEventsLogged {
		t.Error("DataEventsLogged should be false when no trails exist")
	}
}

func TestLoadWithOptions_CloudTrailAdvancedSelector(t *testing.T) {
	trailARN := "arn:aws:cloudtrail:us-east-1:123456789012:trail/advanced-trail"
	resourceTypeField := "resources.type"
	opts := []Option{
		WithS3Client(&mockS3Client{}),
		WithCloudTrailClient(&mockCloudTrailClient{
			describeResp: &cloudtrailOutput{
				TrailList: []cloudtrailtypes.Trail{
					{TrailARN: &trailARN},
				},
			},
			selectorsResp: &selectorsOutput{
				AdvancedEventSelectors: []cloudtrailtypes.AdvancedEventSelector{
					{
						FieldSelectors: []cloudtrailtypes.AdvancedFieldSelector{
							{
								Field:  &resourceTypeField,
								Equals: []string{"AWS::S3::Object"},
							},
						},
					},
				},
			},
		}),
	}
	result, err := LoadWithOptions(testConfig("my-bucket"), opts...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	payload := result.(Payload)

	if payload.CloudTrail == nil {
		t.Fatal("CloudTrail is nil")
	}
	if !payload.CloudTrail.DataEventsLogged {
		t.Error("DataEventsLogged should be true for advanced event selector matching S3")
	}
}

// Type aliases to keep test code concise
type cloudtrailOutput = cloudtrail.DescribeTrailsOutput
type selectorsOutput = cloudtrail.GetEventSelectorsOutput
