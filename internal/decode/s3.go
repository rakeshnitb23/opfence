package decode

import (
	"net/url"
	"strings"

	"github.com/rakeshnitb23/opfence/internal/request"
)

// s3Subresources are query keys that select an S3 sub-resource, checked in
// this order when a request carries several.
var s3Subresources = []string{
	"delete", "uploadId", "uploads", "policy", "acl", "publicAccessBlock", "policyStatus",
	"versioning", "lifecycle", "encryption", "cors", "website", "tagging", "replication",
	"ownershipControls", "object-lock", "retention", "legal-hold", "logging", "notification",
	"location", "versions", "restore", "accelerate", "requestPayment", "intelligent-tiering",
	"inventory", "metrics", "analytics", "attributes", "select",
}

// s3Bucket splits an S3 request into bucket and key. Virtual-hosted requests
// carry the bucket in the host (bucket.s3.region.amazonaws.com); path-style
// requests carry it in the first path segment.
func s3Bucket(r *request.Request) (bucket, key string, ok bool) {
	labels := strings.Split(r.Host, ".")
	idx := -1
	for i, l := range labels {
		if l == "s3" || strings.HasPrefix(l, "s3-") {
			idx = i
			break
		}
	}
	if idx < 0 {
		return "", "", false
	}
	if strings.Contains(r.Host, "s3-control") || strings.Contains(r.Host, "s3-outposts") || strings.HasPrefix(labels[idx], "s3-accesspoint") {
		return "", "", false
	}
	segs, okPath := request.NormalizePath(r.Path)
	if !okPath {
		return "", "", false
	}
	unesc := func(ss []string) (string, bool) {
		parts := make([]string, len(ss))
		for i, s := range ss {
			v, err := url.PathUnescape(s)
			if err != nil {
				return "", false
			}
			parts[i] = v
		}
		return strings.Join(parts, "/"), true
	}
	if idx > 0 {
		bucket = strings.Join(labels[:idx], ".")
		key, ok = unesc(segs)
		return bucket, key, ok
	}
	if len(segs) == 0 {
		return "", "", true
	}
	bucket, ok = unesc(segs[:1])
	if !ok {
		return "", "", false
	}
	key, ok = unesc(segs[1:])
	return bucket, key, ok
}

// s3Operation fills in the S3 action from the method, bucket, key and
// sub-resource. Combinations it does not recognise leave Action empty.
func s3Operation(r *request.Request, op *Operation) {
	bucket, key, ok := s3Bucket(r)
	if !ok {
		op.Error = "cannot tell the S3 bucket and key from this request"
		return
	}
	op.Args = map[string]any{}
	for k, v := range valuesToMap(r.Query) {
		if !strings.HasPrefix(k, "X-Amz-") {
			op.Args[k] = v
		}
	}
	if bucket != "" {
		op.Args["Bucket"] = bucket
	}
	if key != "" {
		op.Args["Key"] = key
	}
	if v := r.Query.Get("versionId"); v != "" {
		op.Args["VersionId"] = v
	}
	headers := map[string]any{}
	for name, vals := range r.Header {
		ln := strings.ToLower(name)
		if strings.HasPrefix(ln, "x-amz-") && ln != "x-amz-date" && ln != "x-amz-content-sha256" && ln != "x-amz-security-token" {
			headers[ln] = strings.Join(vals, ",")
		}
	}
	op.Args["headers"] = headers

	sub := ""
	for _, s := range s3Subresources {
		if _, ok := r.Query[s]; ok {
			sub = s
			break
		}
	}
	op.Action = s3Action(r.Method, bucket != "", key != "", sub, r.Query.Get("list-type") == "2", r.Header.Get("X-Amz-Copy-Source") != "")
	if r.BodyErr != nil && op.Action == "DeleteObjects" {
		op.Error = r.BodyErr.Error()
	}
}

func s3Action(method string, hasBucket, hasKey bool, sub string, listV2, copySource bool) string {
	if !hasBucket {
		if method == "GET" && sub == "" {
			return "ListBuckets"
		}
		return ""
	}
	bucketSub := map[string]string{
		"policy": "BucketPolicy", "acl": "BucketAcl", "publicAccessBlock": "PublicAccessBlock",
		"versioning": "BucketVersioning", "lifecycle": "BucketLifecycleConfiguration",
		"encryption": "BucketEncryption", "cors": "BucketCors", "website": "BucketWebsite",
		"tagging": "BucketTagging", "replication": "BucketReplication",
		"ownershipControls": "BucketOwnershipControls", "object-lock": "ObjectLockConfiguration",
		"logging": "BucketLogging", "notification": "BucketNotificationConfiguration",
		"accelerate": "BucketAccelerateConfiguration", "requestPayment": "BucketRequestPayment",
		"intelligent-tiering": "BucketIntelligentTieringConfiguration", "inventory": "BucketInventoryConfiguration",
		"metrics": "BucketMetricsConfiguration", "analytics": "BucketAnalyticsConfiguration",
	}
	objectSub := map[string]string{
		"acl": "ObjectAcl", "tagging": "ObjectTagging", "retention": "ObjectRetention",
		"legal-hold": "ObjectLegalHold", "attributes": "ObjectAttributes",
	}
	if !hasKey {
		switch method {
		case "GET":
			switch sub {
			case "":
				if listV2 {
					return "ListObjectsV2"
				}
				return "ListObjects"
			case "versions":
				return "ListObjectVersions"
			case "uploads":
				return "ListMultipartUploads"
			case "location":
				return "GetBucketLocation"
			case "policyStatus":
				return "GetBucketPolicyStatus"
			case "lifecycle":
				return "GetBucketLifecycleConfiguration"
			}
			if n, ok := bucketSub[sub]; ok {
				return "Get" + n
			}
		case "HEAD":
			if sub == "" {
				return "HeadBucket"
			}
		case "PUT":
			if sub == "" {
				return "CreateBucket"
			}
			if n, ok := bucketSub[sub]; ok {
				return "Put" + n
			}
		case "DELETE":
			switch sub {
			case "":
				return "DeleteBucket"
			case "lifecycle":
				return "DeleteBucketLifecycle"
			case "policy", "publicAccessBlock", "encryption", "cors", "website", "tagging", "replication", "ownershipControls", "intelligent-tiering", "inventory", "metrics", "analytics":
				return "Delete" + bucketSub[sub]
			}
		case "POST":
			switch sub {
			case "delete":
				return "DeleteObjects"
			case "":
				return "PostObject"
			}
		}
		return ""
	}
	switch method {
	case "GET":
		switch sub {
		case "":
			return "GetObject"
		case "uploadId":
			return "ListParts"
		}
		if n, ok := objectSub[sub]; ok {
			return "Get" + n
		}
	case "HEAD":
		if sub == "" {
			return "HeadObject"
		}
	case "PUT":
		switch sub {
		case "":
			if copySource {
				return "CopyObject"
			}
			return "PutObject"
		case "uploadId":
			if copySource {
				return "UploadPartCopy"
			}
			return "UploadPart"
		}
		if n, ok := objectSub[sub]; ok && sub != "attributes" {
			return "Put" + n
		}
	case "DELETE":
		switch sub {
		case "":
			return "DeleteObject"
		case "tagging":
			return "DeleteObjectTagging"
		case "uploadId":
			return "AbortMultipartUpload"
		}
	case "POST":
		switch sub {
		case "uploads":
			return "CreateMultipartUpload"
		case "uploadId":
			return "CompleteMultipartUpload"
		case "restore":
			return "RestoreObject"
		case "select":
			return "SelectObjectContent"
		}
	}
	return ""
}
