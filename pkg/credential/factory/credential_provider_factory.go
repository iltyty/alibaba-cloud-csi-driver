package credential_provider_factory

import (
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/auth"
	cred "github.com/aliyun/credentials-go/credentials"
)

func GetOpenSDKV1Signer(ramRoleArn string) (auth.Signer, error) {
	return nil, nil
}

func GetOpenSDKV2CredProvider(ramRoleArn string) (cred.Credential, error) {
	return nil, nil
}
