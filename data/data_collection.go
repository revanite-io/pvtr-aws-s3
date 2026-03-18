package data

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/privateerproj/privateer-sdk/config"
)

// Payload contains all AWS S3 bucket data required for evaluation steps.
type Payload struct {
	Config *config.Config

	// Bucket versioning configuration
	Versioning *VersioningData

	// Server-side encryption configuration
	Encryption *EncryptionData

	// Object Lock configuration
	ObjectLock *ObjectLockData

	// Public access block configuration
	PublicAccessBlock *PublicAccessBlockData

	// Access logging configuration
	Logging *LoggingData

	// Bucket policy analysis
	BucketPolicy *BucketPolicyData

	// CloudTrail data event logging
	CloudTrail *CloudTrailData

	// Resource metadata
	BucketName string
	Region     string
}

// VersioningData contains S3 bucket versioning configuration.
type VersioningData struct {
	Status    *string // "Enabled", "Suspended", or ""
	MFADelete *string // "Enabled", "Disabled", or ""
}

// EncryptionData contains S3 bucket encryption configuration.
type EncryptionData struct {
	SSEAlgorithm     *string // "aws:kms", "AES256", "aws:kms:dsse"
	KMSMasterKeyID   *string
	BucketKeyEnabled *bool
}

// ObjectLockData contains S3 Object Lock configuration.
type ObjectLockData struct {
	Enabled          *bool
	DefaultRetention *RetentionData
}

// RetentionData contains Object Lock default retention settings.
type RetentionData struct {
	Mode  *string // "COMPLIANCE", "GOVERNANCE"
	Days  *int32
	Years *int32
}

// PublicAccessBlockData contains S3 public access block configuration.
type PublicAccessBlockData struct {
	BlockPublicAcls       *bool
	BlockPublicPolicy     *bool
	IgnorePublicAcls      *bool
	RestrictPublicBuckets *bool
}

// LoggingData contains S3 server access logging configuration.
type LoggingData struct {
	Enabled       bool
	TargetBucket  *string
	TargetPrefix  *string
	LogBucketTags map[string]string
}

// BucketPolicyData contains analyzed bucket policy information.
type BucketPolicyData struct {
	HasSSLOnlyPolicy     bool
	HasKMSKeyRestriction bool
	PolicyJSON           string
}

// CloudTrailData contains CloudTrail data event logging configuration.
type CloudTrailData struct {
	DataEventsLogged bool
	TrailARN         *string
}

// Loader is the SDK-compatible entrypoint.
func Loader(cfg *config.Config) (any, error) {
	return LoadWithOptions(cfg)
}

// LoadWithOptions is the testable entrypoint with functional options.
func LoadWithOptions(cfg *config.Config, opts ...Option) (any, error) {
	options := &loaderOptions{}
	for _, opt := range opts {
		opt(options)
	}

	bucketName := cfg.GetString("bucketname")
	if bucketName == "" {
		return nil, fmt.Errorf("required config 'bucketname' is not provided")
	}

	payload := Payload{
		Config:     cfg,
		BucketName: bucketName,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create clients if not injected
	if options.s3Client == nil || options.cloudTrailClient == nil {
		awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to load AWS config: %v", err)
		}

		if options.s3Client == nil {
			options.s3Client = s3.NewFromConfig(awsCfg)
		}
		if options.cloudTrailClient == nil {
			options.cloudTrailClient = cloudtrail.NewFromConfig(awsCfg)
		}
	}

	// Fetch bucket location (critical)
	region, err := fetchBucketLocation(ctx, options.s3Client, bucketName)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch bucket location: %v", err)
	}
	payload.Region = region

	// Non-critical fetches: populate nil on failure
	payload.Versioning = fetchVersioning(ctx, options.s3Client, bucketName)
	payload.Encryption = fetchEncryption(ctx, options.s3Client, bucketName)
	payload.ObjectLock = fetchObjectLock(ctx, options.s3Client, bucketName)
	payload.PublicAccessBlock = fetchPublicAccessBlock(ctx, options.s3Client, bucketName)
	payload.Logging = fetchLogging(ctx, options.s3Client, bucketName)
	payload.BucketPolicy = fetchBucketPolicy(ctx, options.s3Client, bucketName)
	payload.CloudTrail = fetchCloudTrail(ctx, options.cloudTrailClient, bucketName)

	return payload, nil
}

func fetchBucketLocation(ctx context.Context, client S3Client, bucketName string) (string, error) {
	resp, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
		Bucket: &bucketName,
	})
	if err != nil {
		return "", err
	}

	// Empty LocationConstraint means us-east-1
	if resp.LocationConstraint == "" {
		return "us-east-1", nil
	}
	return string(resp.LocationConstraint), nil
}

func fetchVersioning(ctx context.Context, client S3Client, bucketName string) *VersioningData {
	resp, err := client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
		Bucket: &bucketName,
	})
	if err != nil {
		return nil
	}

	v := &VersioningData{}
	status := string(resp.Status)
	if status != "" {
		v.Status = &status
	}
	mfaDelete := string(resp.MFADelete)
	if mfaDelete != "" {
		v.MFADelete = &mfaDelete
	}
	return v
}

func fetchEncryption(ctx context.Context, client S3Client, bucketName string) *EncryptionData {
	resp, err := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
		Bucket: &bucketName,
	})
	if err != nil {
		return nil
	}

	if resp.ServerSideEncryptionConfiguration == nil || len(resp.ServerSideEncryptionConfiguration.Rules) == 0 {
		return nil
	}

	rule := resp.ServerSideEncryptionConfiguration.Rules[0]
	enc := &EncryptionData{}
	if rule.ApplyServerSideEncryptionByDefault != nil {
		algo := string(rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm)
		enc.SSEAlgorithm = &algo
		if rule.ApplyServerSideEncryptionByDefault.KMSMasterKeyID != nil {
			enc.KMSMasterKeyID = rule.ApplyServerSideEncryptionByDefault.KMSMasterKeyID
		}
	}
	enc.BucketKeyEnabled = rule.BucketKeyEnabled
	return enc
}

func fetchObjectLock(ctx context.Context, client S3Client, bucketName string) *ObjectLockData {
	resp, err := client.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{
		Bucket: &bucketName,
	})
	if err != nil {
		return nil
	}

	if resp.ObjectLockConfiguration == nil {
		return nil
	}

	enabled := resp.ObjectLockConfiguration.ObjectLockEnabled == s3types.ObjectLockEnabledEnabled
	ol := &ObjectLockData{
		Enabled: &enabled,
	}

	if resp.ObjectLockConfiguration.Rule != nil && resp.ObjectLockConfiguration.Rule.DefaultRetention != nil {
		dr := resp.ObjectLockConfiguration.Rule.DefaultRetention
		ret := &RetentionData{}
		mode := string(dr.Mode)
		if mode != "" {
			ret.Mode = &mode
		}
		if dr.Days != nil {
			ret.Days = dr.Days
		}
		if dr.Years != nil {
			ret.Years = dr.Years
		}
		ol.DefaultRetention = ret
	}

	return ol
}

func fetchPublicAccessBlock(ctx context.Context, client S3Client, bucketName string) *PublicAccessBlockData {
	resp, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
		Bucket: &bucketName,
	})
	if err != nil {
		return nil
	}

	if resp.PublicAccessBlockConfiguration == nil {
		return nil
	}

	cfg := resp.PublicAccessBlockConfiguration
	return &PublicAccessBlockData{
		BlockPublicAcls:       cfg.BlockPublicAcls,
		BlockPublicPolicy:     cfg.BlockPublicPolicy,
		IgnorePublicAcls:      cfg.IgnorePublicAcls,
		RestrictPublicBuckets: cfg.RestrictPublicBuckets,
	}
}

func fetchLogging(ctx context.Context, client S3Client, bucketName string) *LoggingData {
	resp, err := client.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{
		Bucket: &bucketName,
	})
	if err != nil {
		return nil
	}

	logging := &LoggingData{}
	if resp.LoggingEnabled != nil {
		logging.Enabled = true
		logging.TargetBucket = resp.LoggingEnabled.TargetBucket
		logging.TargetPrefix = resp.LoggingEnabled.TargetPrefix

		// Fetch tags of the log bucket
		if resp.LoggingEnabled.TargetBucket != nil {
			logging.LogBucketTags = fetchBucketTags(ctx, client, *resp.LoggingEnabled.TargetBucket)
		}
	}

	return logging
}

func fetchBucketTags(ctx context.Context, client S3Client, bucketName string) map[string]string {
	resp, err := client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{
		Bucket: &bucketName,
	})
	if err != nil {
		return nil
	}

	tags := make(map[string]string)
	for _, tag := range resp.TagSet {
		if tag.Key != nil && tag.Value != nil {
			tags[*tag.Key] = *tag.Value
		}
	}
	return tags
}

// bucketPolicyStatement represents a single statement in an S3 bucket policy.
type bucketPolicyStatement struct {
	Sid       string      `json:"Sid"`
	Effect    string      `json:"Effect"`
	Action    interface{} `json:"Action"` // string or []string
	Condition interface{} `json:"Condition"`
}

// bucketPolicyDocument represents an S3 bucket policy document.
type bucketPolicyDocument struct {
	Statement []bucketPolicyStatement `json:"Statement"`
}

func fetchBucketPolicy(ctx context.Context, client S3Client, bucketName string) *BucketPolicyData {
	resp, err := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
		Bucket: &bucketName,
	})
	if err != nil {
		return nil
	}

	if resp.Policy == nil {
		return nil
	}

	bp := &BucketPolicyData{
		PolicyJSON: *resp.Policy,
	}

	var doc bucketPolicyDocument
	if err := json.Unmarshal([]byte(*resp.Policy), &doc); err != nil {
		return bp
	}

	for _, stmt := range doc.Statement {
		if stmt.Effect != "Deny" {
			continue
		}

		condJSON, err := json.Marshal(stmt.Condition)
		if err != nil {
			continue
		}
		condStr := string(condJSON)

		// Check for SSL-only policy
		if strings.Contains(condStr, "aws:SecureTransport") && strings.Contains(condStr, "false") {
			bp.HasSSLOnlyPolicy = true
		}

		// Check for KMS key restriction
		if strings.Contains(condStr, "s3:x-amz-server-side-encryption-aws-kms-key-id") {
			bp.HasKMSKeyRestriction = true
		}
	}

	return bp
}

func fetchCloudTrail(ctx context.Context, client CloudTrailClient, bucketName string) *CloudTrailData {
	trails, err := client.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return nil
	}

	ct := &CloudTrailData{}
	bucketARNPrefix := fmt.Sprintf("arn:aws:s3:::%s/", bucketName)

	for _, trail := range trails.TrailList {
		if trail.TrailARN == nil {
			continue
		}

		selectors, err := client.GetEventSelectors(ctx, &cloudtrail.GetEventSelectorsInput{
			TrailName: trail.TrailARN,
		})
		if err != nil {
			continue
		}

		// Check classic event selectors
		for _, es := range selectors.EventSelectors {
			for _, dr := range es.DataResources {
				if dr.Type == nil || *dr.Type != "AWS::S3::Object" {
					continue
				}
				for _, value := range dr.Values {
					if value == bucketARNPrefix || value == "arn:aws:s3" {
						ct.DataEventsLogged = true
						ct.TrailARN = trail.TrailARN
						return ct
					}
				}
			}
		}

		// Check advanced event selectors
		for _, aes := range selectors.AdvancedEventSelectors {
			for _, fc := range aes.FieldSelectors {
				if fc.Field == nil {
					continue
				}
				if *fc.Field == "resources.ARN" {
					for _, val := range fc.StartsWith {
						if val == bucketARNPrefix || val == "arn:aws:s3" {
							ct.DataEventsLogged = true
							ct.TrailARN = trail.TrailARN
							return ct
						}
					}
				}
				if *fc.Field == "resources.type" {
					for _, eq := range fc.Equals {
						if eq == "AWS::S3::Object" {
							ct.DataEventsLogged = true
							ct.TrailARN = trail.TrailARN
							return ct
						}
					}
				}
			}
		}
	}

	return ct
}
