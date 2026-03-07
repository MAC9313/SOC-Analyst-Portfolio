<H3>Project Logical Diagram</H3>

![](./Attachments/Pasted%20image%2020260302011801.png)

<details>
<summary><b>Deploying Virtual Machines</b></summary>
<br>
  
To begin this project, three virtual machines will need to be set up and a firewall group with some initial rules will be created to ensure the instances are secure from the external network. It is important that all three instances are connected to the firewall group for the rules to be applied. Just for clarification, the source IP address in the firewall rules is my public IP address, therefore I will be able to connect to these machines if I'm on my current network. 

`Virtual Machines`

![](./Attachments/Pasted%20image%2020260302135619.png)

`Firewall Rules` 

![](./Attachments/Screenshot%202026-03-02%20134335.png)

![](./Attachments/Pasted%20image%2020260302140431.png)

The next step is to enable VPC by selecting "Attach VPC" in the VPC Networks section, which can be seen the image above. Afterwards, the machines need to be configured to be able to communicate with one another on VPC. So the next step is to RDP into the virtual machines to try and establish a network connection. Initial testing of network connectivity show that the machines were unable to communicate with one another.

![](./Attachments/Pasted%20image%2020260302145523.png)


Viewing the network interfaces showed that the VPC was not connected and the Ethernet Adapter has an APIPA address.

```CMD
ipconfig /all
```

![](./Attachments/Pasted%20image%2020260302142351.png)

The interface was set to obtain an IP address automatically, therefore the IP was manually configured to the VPC assigned by the cloud provider. After doing this to both Windows machines, they were able to communicate with one another.

![](./Attachments/Pasted%20image%2020260302144922.png)

![](./Attachments/Pasted%20image%2020260302150257.png)

After successful connection to the Linux machine through SSH, network connectivity to the Windows machines were tested and successful.

![](./Attachments/Pasted%20image%2020260302150921.png)

</details>

<details>
  
<summary><b>Active Directory Set Up</b></summary>
<br>

On the CyberDefender-ADDC01, Server Manager will be used to install Active Directory and promote the server to a Domain Controller.

![](./Attachments/Pasted%20image%2020260302152028.png)

![](./Attachments/Pasted%20image%2020260302152351.png)

![](./Attachments/Pasted%20image%2020260302152622.png)

After installation of the Active Directory services, there is a warning flag in the top right. Click on the warning flag and promote the server to a Domain Controller.

![](./Attachments/Pasted%20image%2020260302153023.png)

Set a strong password: Datsyuk@134013 and then install 

![](./Attachments/Pasted%20image%2020260302153525.png)

After installing the machine will restart and should have Active Directory services upon signing back in.

![](./Attachments/Pasted%20image%2020260302154039.png)

Next, a new user is going to be created.

![](./Attachments/Pasted%20image%2020260302154504.png)

Next task is to go to the `CyberDefender-TestMachine` to join the newly created Domain. Follow the steps illustrated below and sign into the domain controller using the Administrator credentials for `CyberDefender-ADDC01`

![](./Attachments/Pasted%20image%2020260302155852.png)

The operation failed as the VPC is currently not connected to a DNS server and therefore could not translate the domain `CyberDefender,` therefore it is necessary to point the test machine to the IP of the domain controller.

![](./Attachments/Pasted%20image%2020260302160735.png)

After making this change, the connection to the CyberDefender domain is successful. After a restart this can be seen by looking at the login page.

![](./Attachments/Pasted%20image%2020260302161522.png)


From the new account that was created on Active Directory, the user can sign in. If RDP access to the Jane Doe account is desired, then make sure that the username uses `CyberDefender\Jane.`Furthermore, if the account is denied remote access, then permissions will need to be given to that user, which is illustrated in the image below.

![](./Attachments/Pasted%20image%2020260302162631.png)

![](./Attachments/Pasted%20image%2020260302163506.png)

</details>

<details>
<summary><b>Splunk Installation</b></summary>
<br>
  
Go to Splunk and use the .deb wget link to copy the command that will be used to download Spunk enterprise on the Ubuntu machine. 

![](./Attachments/Pasted%20image%2020260302170405.png)


![](./Attachments/Pasted%20image%2020260302170720.png)

![](./Attachments/Pasted%20image%2020260302171131.png)

Maneuver to /opt/splunk/bin to view Splunks binaries.

![](./Attachments/Pasted%20image%2020260302171401.png)


`Start Splunk Binary`
```Bash
./splunk start
```

After creating a username and password, the Splunk web interface is created. Navigate to the Splunk interface by using http:\//vultr:8000. In place of vultr, use the IP address of the Linux machine, not the VPC address. It will be necessary to create a new firewall rule to communicate with this address.

![](./Attachments/Screenshot%202026-03-02%20173356.png)

Still was not able to get the Splunk instance to appear on the web browser, so further troubleshooting was needed. On the Ubuntu machine, a rule was created to allow traffic to and from port 8000 which corrected the problem.

```Bash
ufw allow 8000
```

Once obtaining access to Splunk, ensure that the desired format is set through profile preferences. Next, install the Splunk Add-On for Microsoft for Windows.


![](./Attachments/Pasted%20image%2020260302181808.png)

Navigate to `Indexes` and create a new index and then proceed to create a new index.

![](./Attachments/Pasted%20image%2020260302182249.png)

Next, go to `Forwarding and Receiving` and configure receiving to listen on port 9997(Splunks Universal Forwarder)

![](./Attachments/Pasted%20image%2020260302183518.png)

Next, Splunk Universal Forwarders will need to be installed on the two Windows machines so that logs can be ingested to Splunk.

![](./Attachments/Pasted%20image%2020260302184731.png)

Navigate through the prompts of the forwarder and use the Ubuntu machines VPC IP to be the receiving indexer.

![](./Attachments/Pasted%20image%2020260302185749.png)

In file explorer, navigate to C:\Program Files\SplunkUniversalForwarder\etc\system. In the default folder, copy `inputs.conf` and place the file into local folder that is in the directory path above. Open notepad, add the following to the end of the file, and save:

```inputs.conf
[WinEventLog://Security]
index = CyberDefender-ad
disabled = false
```

![](./Attachments/Screenshot%202026-03-02%20191237.png)

For configuration changes to take effect, restart the Splunk Forwarder service. 

![](./Attachments/Pasted%20image%2020260302192019.png)

`Apply A Firewall Rule To Allow Universal Fowarder Traffic`

```bash
ufw allow 9997
```

Upon allowing traffic through to the Universal Forwarder and configuring the forwarder on both machines, the Splunk Enterprise platform has ingested their logs.

![](./Attachments/Pasted%20image%2020260302195741.png)

For the upcoming SOAR configuration, an alert will be created that will detect unauthorized login attempts to the Windows machine by setting up a query that triggers based on logins that are not happening from the organizations public IP address, which in this case is 199. Write the query in search and reporting, then save as an alert .

```Splunk
index="cyberdefender-ad" EventCode=4624 (Logon_Type=7 OR Logon_Type=10) Source_Network_Address=* Source_Network_Address!='-' Source_Network_Address!=199* 
| stats count by _time, ComputerName,Source_Network_Address,user, Logon_Type
```

![](./Attachments/Pasted%20image%2020260303153153.png)

</details>

<details>
<summary><b>SOAR Configuration</b></summary>
<br>
  
  At `shuffler.io`, start off by creating a workflow.

![](./Attachments/Pasted%20image%2020260303135943.png)


Add a webhook and copy the url into the previously made alert on Splunk.

![](./Attachments/Pasted%20image%2020260303153852.png)

![](./Attachments/Pasted%20image%2020260303154015.png)

After saving the alert, starting the webhook on shuffle will begin to ingest alerts that are created by Splunk.

![](./Attachments/Pasted%20image%2020260303155415.png)

A Slack account is needed to proceed with the next step and a workflow needs to be added in https://slack.com.  After Slack was added to the workflow, there was a problem authenticating with OAuth. Therefore, the workaround was creating an app using the following steps.
1. While logged into Slack, navigate to https://api.slack.com/apps/ and create a new app

![](./Attachments/Pasted%20image%2020260303170836.png)

2. Use the Client ID and the Client Secret with the scope set as `chat:write` and `channel:read` to get the redirect link needed to authenticate. Note that it is bad security hygiene to reveal a secret key, but this is for a test project and the key was regenerated before posting to github.  

![](./Attachments/Pasted%20image%2020260303171144.png)


![](./Attachments/Pasted%20image%2020260303171548.png)


3. In `OAuth and Permissions,` use the link in the error message and add the redirect link. Add `channels:read` and `chat:write` to the scope.

![](./Attachments/Pasted%20image%2020260303171852.png)

4. Proceed to login.
![](./Attachments/Pasted%20image%2020260303172600.png)

After authentication, created a new channel in Slack called alerts, which will receive the alerts from the webhook that is connected to Splunk. It is important to add the Slack app to the channel where the notifications are desired. Next insert the channel name into the Slack app on Shuffle.

![](./Attachments/Pasted%20image%2020260305142925.png)

![](./Attachments/Pasted%20image%2020260305143302.png)

Next, run the workflow with Splunk webhook and Shuffle(Alert Generation) connected. After, insert the desired alert contents in the text parameters on shuffle using the autocomplete text function. Finally, begin the workflow and alerts should be generated to the alerts channel on Slack.

![](./Attachments/Pasted%20image%2020260305143739.png)

![](./Attachments/Pasted%20image%2020260305144307.png)

Next the User Input action is put into the shuffle workflow to send an email to the SOC analyst when an alert is generated.

![](./Attachments/Pasted%20image%2020260305150010.png)

![](./Attachments/Pasted%20image%2020260307013046.png)

Next, the Active Directory app is added to the workflow. There was a problem with  authenticating to the domain as there was a network failure. It turned out the issue had to do with Shuffle not being able to connect to the AD Domain that is behind the VPC. Just to not that port 389 must be able to receive inbound traffic. 

![](./Attachments/Pasted%20image%2020260307112037.png)

Therefore, Docker was installed and the VPC address was set up so the bridge knows which network interface to use for internal traffic.

**1. Install Docker**
```Bash
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh
```

**2. Initialize Docker Swarm** using the **Private VPC IP** of the Ubuntu machine (e.g., 10.5.96.4) to ensure security automation traffic stays off the public internet.
```Bash
docker swarm init --advertise-addr [VPC_IP]
```

Shuffle requires an overlay network to communicate between the bridge (Orborus) and the workers it spawns.

**3. Create the Overlay Network**
```Bash
docker network create --driver overlay --attachable shuffle_swarm_executions
```

Next, in Shuffles admin section, create a location and acquire the Docker command. The command is specialized for VPC environments. It bypasses common DNS and networking conflicts by forcing a standalone configuration and local worker routing.

**4. Run the Orborus Container** Replace `YOUR_AUTH_KEY` and `YOUR_ORG_ID` with the values generated when you create a new "Location" in the Shuffle Cloud UI.

![](./Attachments/Pasted%20image%2020260307111208.png)

**5. Verify the Handshake** Wait 20 seconds, then check that the tunnel is open.

```Bash
docker logs -f shuffle-orborus
```

**Goal:** `[INFO] Waiting for executions at https://california.shuffler.io...`

It is important to note that the Shuffle workflow must be in the newly created location for the connection to Active Directory to be successful. The current workflow is in the following illustration.

![](./Attachments/Pasted%20image%2020260307012456.png)

After executing the workflow, the User Action will send an email and wait for the user response before disabling the user. Copy the True link from the email into a browser and confirm the execution by clicking continue.

![](./Attachments/Pasted%20image%2020260307013342.png)


![](./Attachments/Pasted%20image%2020260307105840.png)

Finally, another Slack application is added to receive the notification that the Active Directory account is disabled. Rerunning the workflow results in Slack receiving the notification. 

![](./Attachments/Pasted%20image%2020260307104158.png)

![](./Attachments/Pasted%20image%2020260307105952.png)

</details>

