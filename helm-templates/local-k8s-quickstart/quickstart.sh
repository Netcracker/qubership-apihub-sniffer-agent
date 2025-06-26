cd ./scripts
./1-deploy-minio-operator.sh
echo "Sleep 10 seconds, wait for minio operator init" ; echo ""
sleep 10

./2-deploy-minio-tenant.sh
#echo "Sleep 10 seconds, wait forminio-tenant init"
#sleep 10

./3-deploy-sniffer-agent.sh
#echo "Sleep 10 seconds, wait for sniffer-agent init"
#sleep 10

## to uninstall all
## helm uninstall qubership-apihub-sniffer-agent -n qubership-apihub-sniffer-agent
## helm uninstall minio-tenant -n minio-tenant
## helm uninstall qubership-apihub-sniffer-agent -n qubership-apihub-sniffer-agent


