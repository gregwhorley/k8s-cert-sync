# k8s-cert-sync
Need to import TLS certs that are managed by your cert-manager instances into ACM? Look no further!

## Primary use case
I have several k8s clusters that all rely on `cert-manager` to issue and renew TLS certificates for ingress hostnames.
I wanted to use `aws-load-balancer-controller` for provisioning and management of ALBs with HTTPS listeners, but I do
not use ACM for anything. I needed a way to automatically import new and renewed TLS certs issued by my `cert-manager`
instances into ACM so that my ALB ingress controller's certificate discovery mechanism can find them.

## How it works
The Python script `import_certs_acm.py` will do the following:
* Fetches a kubernetes secret that contains the TLS cert chain and private key that was created by `cert-manager`
* Inspects the TLS cert imported into ACM for its expiration date
* If no existing cert is found in ACM, it will import the new TLS cert chain and private key
* If found, and expiration date falls within configurable threshold, it will extract the cert chain and key from the k8s secret and import into ACM

## Deployment guide
I decided to deploy the script into my k8s clusters and use a combination of k8s RBAC and IRSA for authz to k8s secrets
and ACM. I use [skaffold](https://skaffold.dev/) in a CI pipeline to render a [Helm](https://helm.sh/) chart with the necessary resources for everything to work,
but I have provided example YAML manifests of the resources for quick testing and POC purposes.

1. Build and publish the image defined in `Dockerfile` to a registry that your k8s cluster(s) are authorized to pull images from
2. Create an IAM role with a trust boundary to the OIDC provider of your cluster [IRSA docs](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html)
3. Allow the following statement to your role's policy
```json
   {
       "Statement": [
           {
               "Action": [
                   "acm:AddTagsToCertificate",
                   "acm:ImportCertificate",
                   "acm:DescribeCertificate",
                   "acm:ListCertificates"
               ],
               "Effect": "Allow",
               "Resource": "*"
           }
       ],
       "Version": "2012-10-17"
   }
```
4. Edit `k8s-manifest.yaml` and change:
   1. The value of `eks.amazonaws.com/role-arn` on line 10 to your IRSA role's ARN
   2. All environment variable values on lines 56-65
   3. The full URL to the published image in step 1 on line 66
   4. The schedule on line 78
5. Run `kubectl apply -f k8s-manifest.yaml`
6. (Optional) If you want to run it on-demand, run `kubectl create job --from=cronjob/k8s-cert-sync test-run`
