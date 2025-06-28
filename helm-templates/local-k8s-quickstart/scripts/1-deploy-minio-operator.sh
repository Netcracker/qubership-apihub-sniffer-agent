#source ./0-lib.sh
echo "---Start MinIO operator deploy using Helm---"
helm repo add minio https://operator.min.io
helm repo update
helm install minio-operator --namespace minio-operator --create-namespace minio/operator 

echo "---Complete MinIO operator deploy using Helm---" ; echo ""

# echo "To uninstall minio operator execute:"
# echo "helm uninstall minio-operator -n minio-operator"
