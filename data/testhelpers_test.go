package data

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// ptr returns a pointer to the given value.
func ptr[T any](v T) *T { return &v }

// mockS3Client satisfies S3Client for tests.
type mockS3Client struct {
	versioningResp      *s3.GetBucketVersioningOutput
	versioningErr       error
	encryptionResp      *s3.GetBucketEncryptionOutput
	encryptionErr       error
	objectLockResp      *s3.GetObjectLockConfigurationOutput
	objectLockErr       error
	publicAccessResp    *s3.GetPublicAccessBlockOutput
	publicAccessErr     error
	loggingResp         *s3.GetBucketLoggingOutput
	loggingErr          error
	policyResp          *s3.GetBucketPolicyOutput
	policyErr           error
	taggingResp         *s3.GetBucketTaggingOutput
	taggingErr          error
	locationResp        *s3.GetBucketLocationOutput
	locationErr         error
}

func (m *mockS3Client) GetBucketVersioning(ctx context.Context, params *s3.GetBucketVersioningInput, optFns ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
	if m.versioningResp != nil || m.versioningErr != nil {
		return m.versioningResp, m.versioningErr
	}
	return &s3.GetBucketVersioningOutput{}, nil
}

func (m *mockS3Client) GetBucketEncryption(ctx context.Context, params *s3.GetBucketEncryptionInput, optFns ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error) {
	if m.encryptionResp != nil || m.encryptionErr != nil {
		return m.encryptionResp, m.encryptionErr
	}
	return &s3.GetBucketEncryptionOutput{}, nil
}

func (m *mockS3Client) GetObjectLockConfiguration(ctx context.Context, params *s3.GetObjectLockConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetObjectLockConfigurationOutput, error) {
	if m.objectLockResp != nil || m.objectLockErr != nil {
		return m.objectLockResp, m.objectLockErr
	}
	return &s3.GetObjectLockConfigurationOutput{}, nil
}

func (m *mockS3Client) GetPublicAccessBlock(ctx context.Context, params *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	if m.publicAccessResp != nil || m.publicAccessErr != nil {
		return m.publicAccessResp, m.publicAccessErr
	}
	return &s3.GetPublicAccessBlockOutput{}, nil
}

func (m *mockS3Client) GetBucketLogging(ctx context.Context, params *s3.GetBucketLoggingInput, optFns ...func(*s3.Options)) (*s3.GetBucketLoggingOutput, error) {
	if m.loggingResp != nil || m.loggingErr != nil {
		return m.loggingResp, m.loggingErr
	}
	return &s3.GetBucketLoggingOutput{}, nil
}

func (m *mockS3Client) GetBucketPolicy(ctx context.Context, params *s3.GetBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
	if m.policyResp != nil || m.policyErr != nil {
		return m.policyResp, m.policyErr
	}
	return &s3.GetBucketPolicyOutput{}, nil
}

func (m *mockS3Client) GetBucketTagging(ctx context.Context, params *s3.GetBucketTaggingInput, optFns ...func(*s3.Options)) (*s3.GetBucketTaggingOutput, error) {
	if m.taggingResp != nil || m.taggingErr != nil {
		return m.taggingResp, m.taggingErr
	}
	return &s3.GetBucketTaggingOutput{}, nil
}

func (m *mockS3Client) GetBucketLocation(ctx context.Context, params *s3.GetBucketLocationInput, optFns ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error) {
	if m.locationResp != nil || m.locationErr != nil {
		return m.locationResp, m.locationErr
	}
	return &s3.GetBucketLocationOutput{
		LocationConstraint: s3types.BucketLocationConstraintUsEast2,
	}, nil
}

// mockCloudTrailClient satisfies CloudTrailClient for tests.
type mockCloudTrailClient struct {
	describeResp  *cloudtrail.DescribeTrailsOutput
	describeErr   error
	selectorsResp *cloudtrail.GetEventSelectorsOutput
	selectorsErr  error
}

func (m *mockCloudTrailClient) DescribeTrails(ctx context.Context, params *cloudtrail.DescribeTrailsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error) {
	if m.describeResp != nil || m.describeErr != nil {
		return m.describeResp, m.describeErr
	}
	return &cloudtrail.DescribeTrailsOutput{}, nil
}

func (m *mockCloudTrailClient) GetEventSelectors(ctx context.Context, params *cloudtrail.GetEventSelectorsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.GetEventSelectorsOutput, error) {
	if m.selectorsResp != nil || m.selectorsErr != nil {
		return m.selectorsResp, m.selectorsErr
	}
	return &cloudtrail.GetEventSelectorsOutput{}, nil
}

// allMockOptions returns functional options with all clients mocked using minimal defaults.
func allMockOptions() []Option {
	return []Option{
		WithS3Client(&mockS3Client{}),
		WithCloudTrailClient(&mockCloudTrailClient{}),
	}
}
