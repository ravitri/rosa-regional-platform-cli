package cluster

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	iamaws "github.com/openshift-online/rosa-regional-platform-cli/internal/aws"
	"github.com/spf13/cobra"
)

const (
	v1Prefix        = "k8s-aws-v1."
	clusterIDHeader = "x-k8s-aws-id"
	// STS ignores X-Amz-Expires but aws-iam-authenticator server validates it is between 0 and 60.
	requestPresignParam = 60
	presignedURLExpiry  = 15 * time.Minute
)

func newGetTokenCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get-token --cluster-id <cluster-id>",
		Short: "Generate an IAM authentication token for a cluster",
		Long: `Generate a presigned STS GetCallerIdentity token for authenticating
to a hosted cluster. This command is used as a kubectl exec credential plugin.

It is equivalent to 'aws-iam-authenticator token -i <cluster-id>'.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			clusterID, _ := cmd.Flags().GetString("cluster-id")
			if clusterID == "" {
				return fmt.Errorf("--cluster-id is required")
			}
			return runGetToken(cmd.Context(), clusterID)
		},
	}

	cmd.Flags().String("cluster-id", "", "Cluster ID to generate a token for")
	_ = cmd.MarkFlagRequired("cluster-id")

	return cmd
}

func runGetToken(ctx context.Context, clusterID string) error {
	cfg, err := iamaws.NewConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	stsClient := sts.NewFromConfig(cfg)
	presignClient := sts.NewPresignClient(stsClient)

	now := time.Now()
	presigned, err := presignClient.PresignGetCallerIdentity(ctx, &sts.GetCallerIdentityInput{},
		withPresignFixedTime(now),
		func(po *sts.PresignOptions) {
			po.ClientOptions = append(po.ClientOptions, func(o *sts.Options) {
				o.APIOptions = append(o.APIOptions,
					smithyhttp.SetHeaderValue(clusterIDHeader, clusterID),
					smithyhttp.SetHeaderValue("X-Amz-Expires", strconv.Itoa(requestPresignParam)),
				)
			})
		},
	)
	if err != nil {
		return fmt.Errorf("failed to presign GetCallerIdentity: %w", err)
	}

	token := v1Prefix + base64.RawURLEncoding.EncodeToString([]byte(presigned.URL))
	expiration := now.Local().Add(presignedURLExpiry - 1*time.Minute)

	out, _ := json.Marshal(execCredential(token, expiration))
	if _, err := fmt.Fprint(os.Stdout, string(out)); err != nil {
		return fmt.Errorf("writing token to stdout: %w", err)
	}
	return nil
}

type presignFixedTimeSigner struct {
	p           sts.HTTPPresignerV4
	signingTime time.Time
}

func (w *presignFixedTimeSigner) PresignHTTP(
	ctx context.Context, credentials aws.Credentials, r *http.Request,
	payloadHash string, service string, region string, _ time.Time,
	optFns ...func(*v4.SignerOptions),
) (string, http.Header, error) {
	return w.p.PresignHTTP(ctx, credentials, r, payloadHash, service, region, w.signingTime, optFns...)
}

func withPresignFixedTime(t time.Time) func(*sts.PresignOptions) {
	return func(o *sts.PresignOptions) {
		o.Presigner = &presignFixedTimeSigner{p: o.Presigner, signingTime: t}
	}
}

func execCredential(token string, expiration time.Time) map[string]interface{} {
	return map[string]interface{}{
		"apiVersion": "client.authentication.k8s.io/v1",
		"kind":       "ExecCredential",
		"status": map[string]interface{}{
			"expirationTimestamp": expiration.UTC().Format(time.RFC3339),
			"token":               token,
		},
	}
}
