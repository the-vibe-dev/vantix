# Vantix Cracking Nodes

Cracking nodes are optional GPU workers controlled by the operator. Vantix ships only generic examples; no private hosts, usernames, keys, or topology are included.

## Setup A Node

1. Install GPU drivers, CUDA/ROCm as required, and hashcat.
2. Create a non-root user for cracking jobs.
3. Create a work directory, for example `~/vantix_crack`.
4. Add an operator-managed SSH key for this lab user.
5. Verify hashcat and GPU visibility:

```bash
ssh -i ~/.ssh/<LAB_KEY> <CRACK_NODE_USER>@<CRACK_NODE_HOST> 'hashcat -I'
```

## Configure

Copy the example and replace placeholders with local operator-owned values:

```bash
cp agent_ops/config/cracking_nodes.example.yaml agent_ops/config/cracking_nodes.yaml
$EDITOR agent_ops/config/cracking_nodes.yaml
```

Expected fields include host, user, SSH key path, remote work directory, staging method, and optional hashcat defaults. Keep the real file ignored and out of version control.

## Use

```bash
bash scripts/crack-node-doctor.sh --node gpu-primary
bash scripts/crack-dispatch.sh --node gpu-primary --hash-file hashes.txt --hash-mode 1000 --wordlist wordlists/rockyou.txt
bash scripts/crack-status.sh --job-id <JOB_ID>
bash scripts/crack-fetch-results.sh --job-id <JOB_ID>
```

Use `staging: scp` for simple deployments. Shared folders such as NFS/SMB are optional and should be configured by the operator only when local policy requires them. The default Vantix runtime does not require shared storage.

## Safety And Hygiene

Only crack hashes you are authorized to test. Do not commit hash files, wordlists with licensing restrictions, private SSH key names, hostnames, usernames, results, or client-specific cracking configuration.
