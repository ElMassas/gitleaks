package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

// TODO this one could probably use some work
func GCPServiceAccount() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Google (GCP) Service-account",
		RuleID:      "gcp-service-account",
		Regex:       regexp.MustCompile(`\"type\": \"service_account\"`),
		Keywords:    []string{`\"type\": \"service_account\"`},
	}

	// validate
	tps := []string{
		`"type": "service_account"`,
	}
	return validate(r, tps, nil)
}

func GCPAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "gcp-api-key",
		Description: "GCP API key",
		Regex:       generateUniqueTokenRegex(`AIza[0-9A-Za-z\\-_]{35}`),
		SecretGroup: 1,
		Keywords: []string{
			"AIza",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("gcp", secrets.NewSecret(`AIza[0-9A-Za-z\\-_]{35}`)),
	}
	return validate(r, tps, nil)
}

func GCPOAuthClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "gcp-oauth-client-secret",
		Description: "GCP OAuth client secrets can be misused to spoof your application",
		Regex:       generateUniqueTokenRegex(`GOCSPX-[a-zA-Z0-9_-]{28}`),
		SecretGroup: 1,
		Keywords: []string{
			"GOCSPX-",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("gcp", secrets.NewSecret(`GOCSPX-[a-zA-Z0-9_-]{28}`)),
	}
	return validate(r, tps, nil)
}
