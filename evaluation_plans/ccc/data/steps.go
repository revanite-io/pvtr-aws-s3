package data

import (
	"github.com/gemaraproj/go-gemara"

	"github.com/revanite-io/pvtr-aws-s3/evaluation_plans/reusable_steps"
)

// --- CN01: KMS Key Trust ---

// KMSEncryptionConfigured verifies that server-side encryption uses a customer-managed KMS key.
func KMSEncryptionConfigured(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	if payload.Encryption == nil {
		return gemara.Unknown, "Encryption configuration not available", confidence
	}

	if payload.Encryption.SSEAlgorithm == nil {
		return gemara.Unknown, "SSE algorithm not available", confidence
	}

	if *payload.Encryption.SSEAlgorithm != "aws:kms" && *payload.Encryption.SSEAlgorithm != "aws:kms:dsse" {
		return gemara.Failed, "Bucket is not using SSE-KMS encryption", confidence
	}

	if payload.Encryption.KMSMasterKeyID == nil || *payload.Encryption.KMSMasterKeyID == "" {
		return gemara.Failed, "SSE-KMS is configured but no KMS key ID is specified (using AWS-managed key instead of customer-managed key)", confidence
	}

	return gemara.Passed, "Bucket is encrypted with a customer-managed KMS key", confidence
}

// BucketPolicyDeniesUntrustedKMSKeys verifies that the bucket policy denies writes with untrusted KMS keys.
func BucketPolicyDeniesUntrustedKMSKeys(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	if payload.BucketPolicy == nil {
		return gemara.Unknown, "Bucket policy data not available", confidence
	}

	if !payload.BucketPolicy.HasKMSKeyRestriction {
		return gemara.Failed, "Bucket policy does not deny writes with untrusted KMS keys", confidence
	}

	return gemara.Passed, "Bucket policy denies writes with untrusted KMS keys", confidence
}

// PreventUntrustedKmsKeysForBucketRead verifies that read requests using untrusted KMS keys are prevented.
func PreventUntrustedKmsKeysForBucketRead(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	if payload.Encryption == nil {
		return gemara.Unknown, "Encryption configuration not available", confidence
	}

	if payload.Encryption.SSEAlgorithm == nil {
		return gemara.Unknown, "SSE algorithm not available", confidence
	}

	if *payload.Encryption.SSEAlgorithm != "aws:kms" && *payload.Encryption.SSEAlgorithm != "aws:kms:dsse" {
		return gemara.Failed, "Bucket is not using SSE-KMS, so KMS key trust cannot be enforced for reads", confidence
	}

	// S3 SSE-KMS decryption uses the key the object was encrypted with.
	// If the bucket policy enforces a specific KMS key on writes, all objects
	// will be encrypted with the trusted key, and reads will inherently use it.
	if payload.BucketPolicy != nil && payload.BucketPolicy.HasKMSKeyRestriction {
		return gemara.Passed, "SSE-KMS is configured and bucket policy restricts KMS key usage on writes, ensuring reads use the trusted key", confidence
	}

	return gemara.NeedsReview, "SSE-KMS is configured but bucket policy does not restrict KMS key usage on writes. Manual verification required to confirm all objects are encrypted with a trusted key", confidence
}

// PreventUntrustedKmsKeysForObjectRead verifies that object read requests using untrusted KMS keys are prevented.
func PreventUntrustedKmsKeysForObjectRead(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	return PreventUntrustedKmsKeysForBucketRead(payloadData)
}

// PreventUntrustedKmsKeysForBucketWrite verifies that write requests using untrusted KMS keys are prevented.
func PreventUntrustedKmsKeysForBucketWrite(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	if payload.Encryption == nil {
		return gemara.Unknown, "Encryption configuration not available", confidence
	}

	if payload.Encryption.SSEAlgorithm == nil {
		return gemara.Unknown, "SSE algorithm not available", confidence
	}

	if *payload.Encryption.SSEAlgorithm != "aws:kms" && *payload.Encryption.SSEAlgorithm != "aws:kms:dsse" {
		return gemara.Failed, "Bucket is not using SSE-KMS, so KMS key trust cannot be enforced for writes", confidence
	}

	if payload.BucketPolicy == nil {
		return gemara.Unknown, "Bucket policy data not available", confidence
	}

	if !payload.BucketPolicy.HasKMSKeyRestriction {
		return gemara.Failed, "Bucket policy does not restrict KMS key usage on writes", confidence
	}

	return gemara.Passed, "SSE-KMS is configured and bucket policy restricts writes to trusted KMS key only", confidence
}

// PreventUntrustedKmsKeysForObjectWrite verifies that object write requests using untrusted KMS keys are prevented.
func PreventUntrustedKmsKeysForObjectWrite(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	return PreventUntrustedKmsKeysForBucketWrite(payloadData)
}

// --- CN02: Uniform Bucket-Level Access ---

// PublicAccessBlockEnabled verifies that all public access block settings are enabled,
// ensuring uniform bucket-level access and preventing object-level ACLs.
func PublicAccessBlockEnabled(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	if payload.PublicAccessBlock == nil {
		return gemara.Unknown, "Public access block configuration not available", confidence
	}

	if payload.PublicAccessBlock.BlockPublicAcls == nil ||
		payload.PublicAccessBlock.BlockPublicPolicy == nil ||
		payload.PublicAccessBlock.IgnorePublicAcls == nil ||
		payload.PublicAccessBlock.RestrictPublicBuckets == nil {
		return gemara.Unknown, "Public access block settings are incomplete", confidence
	}

	if !*payload.PublicAccessBlock.BlockPublicAcls {
		return gemara.Failed, "BlockPublicAcls is not enabled", confidence
	}
	if !*payload.PublicAccessBlock.IgnorePublicAcls {
		return gemara.Failed, "IgnorePublicAcls is not enabled", confidence
	}
	if !*payload.PublicAccessBlock.BlockPublicPolicy {
		return gemara.Failed, "BlockPublicPolicy is not enabled", confidence
	}
	if !*payload.PublicAccessBlock.RestrictPublicBuckets {
		return gemara.Failed, "RestrictPublicBuckets is not enabled", confidence
	}

	return gemara.Passed, "All public access block settings are enabled, enforcing uniform bucket-level access", confidence
}

// PublicAccessBlockEnabledForDenial verifies public access block for the denial case of uniform access.
func PublicAccessBlockEnabledForDenial(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	return PublicAccessBlockEnabled(payloadData)
}

// --- CN03: Bucket Deletion Recovery ---

// ObjectLockEnabled verifies that Object Lock is enabled on the bucket, allowing recovery after deletion.
func ObjectLockEnabled(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	if payload.ObjectLock == nil {
		return gemara.Unknown, "Object Lock configuration not available", confidence
	}

	if payload.ObjectLock.Enabled == nil {
		return gemara.Unknown, "Object Lock enabled property not available", confidence
	}

	if !*payload.ObjectLock.Enabled {
		return gemara.Failed, "Object Lock is not enabled on the bucket", confidence
	}

	// Also check versioning since Object Lock requires it
	if payload.Versioning == nil || payload.Versioning.Status == nil || *payload.Versioning.Status != "Enabled" {
		return gemara.Failed, "Object Lock is enabled but versioning is not in Enabled state", confidence
	}

	return gemara.Passed, "Object Lock and versioning are enabled, allowing object recovery after deletion", confidence
}

// RetentionPolicyLocked verifies that the retention policy uses COMPLIANCE mode and cannot be modified.
func RetentionPolicyLocked(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	if payload.ObjectLock == nil {
		return gemara.Unknown, "Object Lock configuration not available", confidence
	}

	if payload.ObjectLock.Enabled == nil || !*payload.ObjectLock.Enabled {
		return gemara.Failed, "Object Lock is not enabled", confidence
	}

	if payload.ObjectLock.DefaultRetention == nil {
		return gemara.Unknown, "Default retention configuration not available", confidence
	}

	if payload.ObjectLock.DefaultRetention.Mode == nil {
		return gemara.Unknown, "Retention mode not available", confidence
	}

	if *payload.ObjectLock.DefaultRetention.Mode != "COMPLIANCE" {
		return gemara.Failed, "Retention mode is GOVERNANCE, not COMPLIANCE. GOVERNANCE mode allows privileged users to modify the retention policy", confidence
	}

	return gemara.Passed, "Retention policy uses COMPLIANCE mode, which cannot be modified or overridden", confidence
}

// --- CN04: Default Retention Policy ---

// DefaultRetentionConfigured verifies that Object Lock has a default retention policy.
func DefaultRetentionConfigured(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	if payload.ObjectLock == nil {
		return gemara.Unknown, "Object Lock configuration not available", confidence
	}

	if payload.ObjectLock.Enabled == nil || !*payload.ObjectLock.Enabled {
		return gemara.Failed, "Object Lock is not enabled, so objects do not receive a default retention policy", confidence
	}

	if payload.ObjectLock.DefaultRetention == nil {
		return gemara.Failed, "Object Lock is enabled but no default retention policy is configured", confidence
	}

	if payload.ObjectLock.DefaultRetention.Mode == nil {
		return gemara.Failed, "Default retention policy has no mode configured", confidence
	}

	hasDuration := (payload.ObjectLock.DefaultRetention.Days != nil && *payload.ObjectLock.DefaultRetention.Days > 0) ||
		(payload.ObjectLock.DefaultRetention.Years != nil && *payload.ObjectLock.DefaultRetention.Years > 0)

	if !hasDuration {
		return gemara.Failed, "Default retention policy has no retention period configured", confidence
	}

	return gemara.Passed, "Object Lock default retention policy is configured, ensuring all uploaded objects receive a retention policy", confidence
}

// DeletionPreventedByRetention verifies that objects under active retention cannot be deleted.
func DeletionPreventedByRetention(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	if payload.ObjectLock == nil {
		return gemara.Unknown, "Object Lock configuration not available", confidence
	}

	if payload.ObjectLock.Enabled == nil || !*payload.ObjectLock.Enabled {
		return gemara.Failed, "Object Lock is not enabled, so retention-based deletion prevention is not active", confidence
	}

	if payload.ObjectLock.DefaultRetention == nil || payload.ObjectLock.DefaultRetention.Mode == nil {
		return gemara.Unknown, "Default retention configuration not available", confidence
	}

	if *payload.ObjectLock.DefaultRetention.Mode == "COMPLIANCE" {
		return gemara.Passed, "Object Lock COMPLIANCE mode prevents deletion of objects under active retention, including by privileged users", confidence
	}

	return gemara.NeedsReview, "Object Lock GOVERNANCE mode is configured. Privileged users with s3:BypassGovernanceRetention permission may be able to delete objects. Manual verification required", confidence
}

// --- CN05: Versioning ---

// VersioningEnabled verifies that versioning is enabled on the bucket.
func VersioningEnabled(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	if payload.Versioning == nil {
		return gemara.Unknown, "Versioning data not available", confidence
	}

	if payload.Versioning.Status == nil {
		return gemara.Unknown, "Versioning status not available", confidence
	}

	if *payload.Versioning.Status != "Enabled" {
		return gemara.Failed, "Versioning is not enabled on the bucket", confidence
	}

	return gemara.Passed, "Versioning is enabled on the bucket", confidence
}

// NewVersionOnModification verifies that modifying an object creates a new version.
func NewVersionOnModification(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	if payload.Versioning == nil || payload.Versioning.Status == nil {
		return gemara.Unknown, "Versioning data not available", confidence
	}

	if *payload.Versioning.Status != "Enabled" {
		return gemara.Failed, "Versioning is not enabled, so new versions cannot be created on modification", confidence
	}

	return gemara.NeedsReview, "Versioning is enabled. Manual verification required to confirm that modifying an object creates a new version with a unique identifier", confidence
}

// PreviousVersionsRecoverable verifies that previous versions of objects can be recovered.
func PreviousVersionsRecoverable(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	if payload.Versioning == nil || payload.Versioning.Status == nil {
		return gemara.Unknown, "Versioning data not available", confidence
	}

	if *payload.Versioning.Status != "Enabled" {
		return gemara.Failed, "Versioning is not enabled, so previous versions cannot be recovered", confidence
	}

	return gemara.NeedsReview, "Versioning is enabled. Manual verification required to confirm that previous versions of objects can be recovered after modification", confidence
}

// VersionsRetainedOnDeletion verifies that versions are retained when an object is deleted.
func VersionsRetainedOnDeletion(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	if payload.Versioning == nil || payload.Versioning.Status == nil {
		return gemara.Unknown, "Versioning data not available", confidence
	}

	if *payload.Versioning.Status != "Enabled" {
		return gemara.Failed, "Versioning is not enabled, so versions cannot be retained on deletion", confidence
	}

	return gemara.NeedsReview, "Versioning is enabled. Manual verification required to confirm that versions are retained when an object is deleted, allowing recovery", confidence
}

// --- CN06: Access Logging ---

// AccessLoggingConfigured verifies that access logs are stored in a separate data store.
func AccessLoggingConfigured(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	// Check S3 server access logging
	s3LoggingEnabled := payload.Logging != nil && payload.Logging.Enabled &&
		payload.Logging.TargetBucket != nil && *payload.Logging.TargetBucket != ""

	// Check CloudTrail data events
	cloudTrailEnabled := payload.CloudTrail != nil && payload.CloudTrail.DataEventsLogged

	if !s3LoggingEnabled && !cloudTrailEnabled {
		return gemara.Failed, "Neither S3 server access logging nor CloudTrail data events are configured for this bucket", confidence
	}

	if s3LoggingEnabled && cloudTrailEnabled {
		return gemara.Passed, "Both S3 server access logging and CloudTrail data events are configured, storing access logs in separate data stores", confidence
	}

	if s3LoggingEnabled {
		return gemara.Passed, "S3 server access logging is configured, storing access logs in a separate bucket", confidence
	}

	return gemara.Passed, "CloudTrail data events are configured for this bucket, storing access logs in a separate data store", confidence
}

// LogBucketHighestSensitivity verifies that the log bucket is classified at the highest sensitivity level.
func LogBucketHighestSensitivity(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	if payload.Logging == nil || !payload.Logging.Enabled {
		return gemara.NeedsReview, "S3 server access logging is not configured. If CloudTrail is used for logging, the CloudTrail S3 bucket should be classified at the highest sensitivity level. Manual verification required", confidence
	}

	if payload.Logging.LogBucketTags == nil {
		return gemara.NeedsReview, "Log bucket tags not available. Manual verification required to confirm the log bucket is classified at the highest sensitivity level", confidence
	}

	sensitivity, ok := payload.Logging.LogBucketTags["sensitivity"]
	if !ok {
		return gemara.Failed, "Log bucket does not have a 'sensitivity' tag", confidence
	}

	if sensitivity != "high" {
		return gemara.Failed, "Log bucket sensitivity tag is '" + sensitivity + "', expected 'high'", confidence
	}

	return gemara.Passed, "Log bucket is tagged with sensitivity=high, classified at the highest sensitivity level", confidence
}

// --- CN07: MFA Delete ---

// MfaDeleteSupported verifies that MFA Delete is available as a configuration option.
func MfaDeleteSupported(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	_, message = reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	// AWS S3 supports MFA Delete as a configuration option on versioned buckets.
	// However, it can only be enabled by the root account user via the AWS CLI.
	// It cannot be managed through Terraform or standard IAM users.
	return gemara.Passed, "AWS S3 supports MFA Delete as a configuration option for versioned buckets. Note: MFA Delete can only be enabled by the root account holder via the AWS CLI", confidence
}

// MfaDeleteEnforced verifies that MFA Delete is enabled and enforced on the bucket.
func MfaDeleteEnforced(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	if payload.Versioning == nil {
		return gemara.Unknown, "Versioning data not available", confidence
	}

	if payload.Versioning.MFADelete == nil {
		return gemara.Unknown, "MFA Delete status not available", confidence
	}

	if *payload.Versioning.MFADelete != "Enabled" {
		return gemara.Failed, "MFA Delete is not enabled on the bucket. MFA Delete can only be enabled by the root account holder via the AWS CLI", confidence
	}

	return gemara.Passed, "MFA Delete is enabled on the bucket, denying deletion requests without MFA validation", confidence
}

// MfaDeletionLogged verifies that deletion attempts are logged with MFA status.
func MfaDeletionLogged(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	// Check if CloudTrail data events are logging for this bucket
	if payload.CloudTrail == nil || !payload.CloudTrail.DataEventsLogged {
		return gemara.Failed, "CloudTrail data events are not configured for this bucket, so deletion attempts are not logged", confidence
	}

	// CloudTrail logs include all S3 API calls including DeleteObject
	// The logs include authentication details which would show MFA status
	return gemara.Passed, "CloudTrail data events are configured, which logs all deletion attempts including authentication details and MFA validation status", confidence
}

// --- CN02 Additional: Bucket Policy SSL ---

// BucketPolicyEnforcesSSL verifies that the bucket policy denies unencrypted transport.
func BucketPolicyEnforcesSSL(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	if payload.BucketPolicy == nil {
		return gemara.Unknown, "Bucket policy data not available", confidence
	}

	if !payload.BucketPolicy.HasSSLOnlyPolicy {
		return gemara.Failed, "Bucket policy does not enforce SSL-only transport", confidence
	}

	return gemara.Passed, "Bucket policy enforces SSL-only transport, denying unencrypted requests", confidence
}
