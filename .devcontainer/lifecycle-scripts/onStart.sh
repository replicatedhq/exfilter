#!/usr/bin/env bash

# Start the cluster here
k3d cluster start exfilter

# Skaffold run
# nohup bash -c 'skaffold dev &' > skaffold.log 2>&1

