/*


Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"fmt"
	pathlib "path"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	vsv1alpha1 "github.com/jmelis/vault-secrets-operator/api/v1alpha1"
	"github.com/jmelis/vault-secrets-operator/pkg/vault"
)

// VaultSecretReconciler reconciles a VaultSecret object
type VaultSecretReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// Reconcile creates and mages the VaultSecrets
// +kubebuilder:rbac:groups=vaultsecrets.devshift.net,resources=vaultsecrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=vaultsecrets.devshift.net,resources=vaultsecrets/status,verbs=get;update;patch
func (r *VaultSecretReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("vaultsecret", req.NamespacedName)
	log.Info("Reconciling")

	vs := &vsv1alpha1.VaultSecret{}
	err := r.Get(ctx, req.NamespacedName, vs)
	if err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}

		log.Error(err, "Could not get resource")
		return ctrl.Result{}, err
	}

	// fetch secret
	secret, err := r.getSecretFromVaultSecret(vs)
	if err != nil && !errors.IsNotFound(err) {
		// error is unknown so log and requeue
		log.Error(err, "Unknown error fetching Secret owned by VaultSecret")
		return ctrl.Result{}, err
	}

	create := secret == nil

	if create || !secretIsReconciled(vs, secret) {
		r.reconcileSecret(vs, create)
	}

	return ctrl.Result{}, nil
}

func secretIsReconciled(vs *vsv1alpha1.VaultSecret, secret *corev1.Secret) bool {
	return secret.Annotations != nil && secret.Annotations["vaultsecrets.devshift.net/path"] != vs.Spec.Path &&
		secret.Annotations["vaultsecrets.devshift.net/version"] != fmt.Sprintf("%d", vs.Spec.Version)
}

// SetupWithManager creates the watchers
func (r *VaultSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&vsv1alpha1.VaultSecret{}).
		Complete(r)
}

func (r *VaultSecretReconciler) reconcileSecret(vs *vsv1alpha1.VaultSecret, create bool) error {
	secret, err := r.newSecretFromVaultSecret(vs)
	if err != nil {
		return r.updateStatusError(vs, err)
	}

	if create {
		err = r.Create(context.Background(), secret)
	} else {
		err = r.Update(context.Background(), secret)
	}

	if err != nil {
		return r.updateStatusError(vs, err)
	}

	return r.updateStatusOK(vs)
}

func (r *VaultSecretReconciler) updateStatusOK(vs *vsv1alpha1.VaultSecret) error {
	r.Log.Info("Setting status OK")
	vs.Status.Reconciled = true
	vs.Status.Error = ""
	return r.Status().Update(context.Background(), vs)
}

func (r *VaultSecretReconciler) updateStatusError(vs *vsv1alpha1.VaultSecret, err error) error {
	r.Log.Info("Setting status Error", "msg", err.Error())
	vs.Status.Reconciled = false
	vs.Status.Error = err.Error()
	return r.Status().Update(context.Background(), vs)
}

func (r *VaultSecretReconciler) newSecretFromVaultSecret(vs *vsv1alpha1.VaultSecret) (*corev1.Secret, error) {
	s := &corev1.Secret{}
	if vs.Spec.Name != "" {
		s.Name = vs.Spec.Name
	} else {
		s.Name = pathlib.Base(vs.Spec.Path)
	}
	s.Namespace = vs.Namespace

	data, err := vault.ReadSecretKV2(vs.Spec.Path, vs.Spec.Version)
	if err != nil {
		return nil, err
	}

	secretData := make(map[string][]byte)
	for key, value := range data {
		secretData[key] = []byte(value)
	}

	s.Data = secretData
	if s.Annotations == nil {
		s.Annotations = make(map[string]string)
	}
	s.Annotations["vaultsecrets.devshift.net/path"] = vs.Spec.Path
	s.Annotations["vaultsecrets.devshift.net/version"] = fmt.Sprintf("%d", vs.Spec.Version)

	err = controllerutil.SetOwnerReference(vs, s, r.Scheme)

	return s, err
}

func (r *VaultSecretReconciler) getSecretFromVaultSecret(vs *vsv1alpha1.VaultSecret) (*corev1.Secret, error) {
	ctx := context.Background()
	secret := &corev1.Secret{}

	name := vs.Spec.Name

	if name == "" {
		name = pathlib.Base(vs.Spec.Path)
	}

	namespacedName := types.NamespacedName{
		Name:      name,
		Namespace: vs.Namespace,
	}

	if err := r.Get(ctx, namespacedName, secret); err != nil {
		return nil, err
	}

	return secret, nil
}
