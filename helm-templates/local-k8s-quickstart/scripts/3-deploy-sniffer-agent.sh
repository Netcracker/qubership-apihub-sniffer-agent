source ./0-lib.sh
echo "---Generate SNIFFER API SECRET---" 

export SNIFFER_API_KEY=$(generate_random_string 20)
export SNIFFER_INTERNAL_KEY=$(generate_random_string 30)
envsubst < ../qubership-apihub-sniffer-agent/local-sniffer-secrets.yaml.template > ../qubership-apihub-sniffer-agent/local-sniffer-secrets.yaml 
echo "SNIFFER_API_KEY:" $SNIFFER_API_KEY
echo "SNIFFER_INTERNAL_KEY:" $SNIFFER_INTERNAL_KEY

echo "---Start SNIFFER-AGENT deploy using Helm---"
helm install qubership-apihub-sniffer-agent -n qubership-apihub-sniffer-agent --create-namespace -f ../qubership-apihub-sniffer-agent/local-k8s-values.yaml -f ../qubership-apihub-sniffer-agent/local-minio-secrets.yaml -f ../qubership-apihub-sniffer-agent/local-sniffer-secrets.yaml  ../../qubership-apihub-sniffer-agent
echo "---Complete SNIFFER-AGENT deploy using Helm---" ; echo ""

#echo "To undeploy sniffer-agent execute:"
#echo "helm uninstall qubership-apihub-sniffer-agent -n qubership-apihub-sniffer-agent"

