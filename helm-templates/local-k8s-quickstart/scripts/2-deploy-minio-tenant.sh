source ./0-lib.sh
echo "---Start MinIO tenant deploy using Helm---"
helm install minio-tenant --namespace minio-tenant --create-namespace -f ../minio/minio-tenant-local-values.yaml minio/tenant

wait_for_pod_ready "myminio-pool-0-0" "minio-tenant" 600

echo "" ; echo "Generate MinIO Accesskey"
export INF_NAME='qubership-apihub'
export DESCRP="($(date +%Y-%m-%d:%H:%M:%S)) needed for sniffer agent and trffic analizer"
# Default MinIO administrative credential
export ADM_USR='minio'
export ADM_PASS='minio123'
export ACC_KEY=$(generate_random_string 20)
export ACC_SEC=$(generate_random_string 30)

kubectl exec -n minio-tenant myminio-pool-0-0  -it -- /bin/sh  -c " mc alias set myminio https://minio.minio-tenant.svc '$ADM_USR' '$ADM_PASS' ;mc admin accesskey create myminio/ --access-key '$ACC_KEY' --secret-key '$ACC_SEC' --name '$INF_NAME'  --description '$DESCRP' "
export MINIO_CRT=$(kubectl get secrets  -n minio-tenant myminio-tls  -o jsonpath={.data.public\\.crt})

envsubst < ../qubership-apihub-sniffer-agent/local-minio-secrets.yaml.template > ../qubership-apihub-sniffer-agent/local-minio-secrets.yaml 

echo ""
echo "Deployed MinIO whith the next credentials"
echo "MINIO_ROOT_USER: $ADM_USR"
echo "MINIO_ROOT_PASSWORD: $ADM_PASS"
echo "MinIO access key: $ACC_KEY"
echo "MinIO access secret: $ACC_SEC"
echo "MinIO TLS certificate: $MINIO_CRT"

echo "---Complete SNIFFER-AGENT deploy using Helm---" ; echo ""

#echo "To undeploy minio tenant execute:"
#echo "helm uninstall minio-tenant -n minio-tenant"

