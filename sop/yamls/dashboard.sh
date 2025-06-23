#!/bin/bash
kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/v2.7.0/aio/deploy/recommended.yaml

kubectl apply -f https://raw.githubusercontent.com/Denis-Golkov/k8s/refs/heads/main/sop/yamls/dashboard-service.yaml

echo "Apply the service account:"

kubectl apply -f https://raw.githubusercontent.com/Denis-Golkov/k8s/refs/heads/main/sop/yamls/service-account.yaml

echo "Apply the RBAC role binding:"

kubectl apply -f https://raw.githubusercontent.com/Denis-Golkov/k8s/refs/heads/main/sop/yamls/rbac.yaml

echo "Generate the access token..."

kubectl apply -f https://raw.githubusercontent.com/Denis-Golkov/k8s/refs/heads/main/sop/yamls/secret.yaml

kubectl get secret admin-user -n kubernetes-dashboard -o jsonpath={".data.token"} | base64 -d

echo "Access the Dashboard at:"

echo "https://{control-plane-public-ip}:30000"

echo "Use the generated token to log in."
