// Package vault implements a wrapper around a Vault API client that retrieves
// credentials from the operating system environment.
package vault

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
)

var clientToken string
var client *api.Client

func init() {
	vaultConfig := api.DefaultConfig()
	vaultConfig.Address = mustGetenv("VAULT_ADDR")

	if clientToken == "" {
		var err error
		client, err = api.NewClient(vaultConfig)
		if err != nil {
			log.WithError(err).Fatal("failed to initialize Vault client")
		}

		roleID := mustGetenv("VAULT_ROLE_ID")
		secretID := mustGetenv("VAULT_SECRET_ID")

		secret, err := client.Logical().Write("auth/approle/login", map[string]interface{}{
			"role_id":   roleID,
			"secret_id": secretID,
		})
		if err != nil {
			log.WithError(err).Fatal("[Vault Client] failed to login to Vault with AppRole")
		}
		clientToken = secret.Auth.ClientToken
	}

	client.SetToken(clientToken)
}

func getClient() *api.Client {
	return client
}

// ReadSecretKV2 returns the KV2 secret. The secretPath should not include be in
// the format of <mountpoint>/<secretpath> and not
// <mountpoint>/data/<secretpath>
func ReadSecretKV2(secretPath string, version int) (map[string]string, error) {
	versionSlice := []string{strconv.Itoa(version)}
	params := map[string][]string{
		"version": versionSlice,
	}

	// inject /data/
	pathComponents := strings.Split(secretPath, "/")
	mountPoint := pathComponents[0]
	secretPath = mountPoint + "/data/" + strings.Join(pathComponents[1:], "/")

	secret, err := getClient().Logical().ReadWithData(secretPath, params)
	if err != nil {
		// likely a permission error
		return nil, errors.New("error fetching secret")
	}

	if secret == nil {
		// secret not found
		return nil, errors.New("secret not found")
	}

	secretData, ok := secret.Data["data"]
	if !ok {
		// this should not happen, this indicates a malformed api request, must be investigated
		return nil, errors.New("error retrieving data from secret")
	}

	data, ok := secretData.(map[string]interface{})
	if !ok {
		// this should not happen, this indicates a malformed api request, must be investigated
		return nil, errors.New("error decoding secret")
	}

	dataString := make(map[string]string)
	for key, value := range data {
		strValue := fmt.Sprintf("%v", value)
		dataString[key] = strValue
	}

	return dataString, nil
}

func mustGetenv(name string) string {
	env := os.Getenv(name)
	if env == "" {
		log.WithField("env", name).Fatal("required environment variable is unset")
	}
	return env
}

func defaultGetenv(name, defaultName string) string {
	env := os.Getenv(name)
	if env == "" {
		env = defaultName
	}
	return env
}
