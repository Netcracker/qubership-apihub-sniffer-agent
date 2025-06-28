cd ./scripts
./1-deploy-minio-operator.sh
echo "Sleep 10 seconds, wait for minio operator init" ; echo ""
sleep 10

./2-deploy-minio-tenant.sh
# the script will wait until the tenant becomes available

./3-deploy-sniffer-agent.sh

## to uninstall all
## helm uninstall qubership-apihub-sniffer-agent -n qubership-apihub-sniffer-agent
## helm uninstall minio-tenant -n minio-tenant
## helm uninstall qubership-apihub-sniffer-agent -n qubership-apihub-sniffer-agent


