---
title: How it works
description: How Exfilter works
---

Exfilter works by running a Daemonset on each node in a Kubernetes cluster, and installing several kprobes and several uprobes to detect (and monitor or prevent) outbound traffic.

Our method here will work for most applications, without requiring any application-level instrumentation.

Some applications may use kernel functions and other ways that Exfilter will not detect.

## kprobes

Exfilter will detect any use of the following kernel methods:

- `sendmsg`

## uprobes

In addition to the kprobes, Exfilter will find and install a uprobe for OpenSSL. This allows Exfilter to build a map of unencrypted traffic and later detect when it's sent over a network connection. Because of this map, Exfilter can (most of the time) provide the same functionality for TLS traffic as it provides for non-TLS traffic.