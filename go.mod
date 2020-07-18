module github.com/jmelis/vault-secrets-operator

go 1.13

require (
	github.com/go-logr/logr v0.1.0
	github.com/google/martian v2.1.0+incompatible
	github.com/hashicorp/vault/api v1.0.4
	github.com/onsi/ginkgo v1.11.0
	github.com/onsi/gomega v1.8.1
	github.com/sirupsen/logrus v1.4.2
	k8s.io/api v0.18.2
	k8s.io/apimachinery v0.18.2
	k8s.io/client-go v0.18.2
	sigs.k8s.io/controller-runtime v0.6.0
)
