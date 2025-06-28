generate_random_string() {
  local length=$1
  cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w $length | head -n 1
}

function wait_for_pod_creation() {
    local pod_name=$1
    local namespace=${2:-default}
    local timeout=${3:-300}  # Default 5 minutes
    local interval=5
    local elapsed=0

    echo "Waiting for Pod $pod_name to be created in namespace $namespace..."

    while [[ $elapsed -lt $timeout ]]; do
        if kubectl get pod "$pod_name" -n "$namespace" --no-headers --ignore-not-found 2>/dev/null | grep -q "^$pod_name"; then
            echo "Pod $pod_name found!"
            return 0
        fi
        sleep $interval
        elapsed=$((elapsed + interval))
        echo "$elapsed seconds elapsed. Waiting for Pod creation..."
    done

    echo "Error: Pod $pod_name was not created within $timeout seconds"
    return 1
}

function wait_for_pod_ready() {
    local pod_name=$1
    local namespace=${2:-default}
    local timeout=${3:-300}

    # First wait for Pod creation
    if ! wait_for_pod_creation "$pod_name" "$namespace" "$timeout"; then
        return 1
    fi

    # Then wait for readiness
    echo "Waiting for Pod $pod_name to become ready..."
    if kubectl wait --namespace "$namespace" --for=condition=Ready --timeout="${timeout}s" pod/"$pod_name"; then
        echo "Pod $pod_name is ready!"
        return 0
    else
        echo "Error: Pod $pod_name did not become Ready within $timeout seconds"
        return 1
    fi
}