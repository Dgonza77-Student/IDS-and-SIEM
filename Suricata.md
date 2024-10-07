# **Network Monitoring and Alert Management with Suricata**

## **Objective**
The goal of this lab activity is to configure and use Suricata to monitor network traffic, create custom rules, and analyze the generated alerts and logs. You will examine prewritten rules, trigger alerts by testing custom rules against network traffic, and analyze the resulting log outputs in Suricata.

### **Skills Learned**
- Configuration and rule creation in Suricata.
- Understanding and analyzing Suricata log files, including `fast.log` and `eve.json`.
- Packet capture analysis using `.pcap` files to simulate network traffic.
- Network security monitoring and alert generation based on custom rules.
- JSON log parsing and understanding Suricata’s event logs.

### **Tools Used**
- **Suricata**: Open-source network monitoring, intrusion detection, and intrusion prevention system.
- **PCAP file**: A packet capture file used to simulate real network traffic for testing.
- **fast.log**: A Suricata log file used for quick checks and alerts.
- **eve.json**: The main Suricata log file for detailed event logging in JSON format.
- **Linux Terminal**: For running Suricata and managing files.

---

### **Lab Instructions**

#### **Scenario**
You are a security analyst tasked with monitoring your employer’s network. Using Suricata, you will create and test custom rules to generate alerts based on specific network traffic conditions.


#### *Task 1: Examination of a custom rule in Suricata*
In order to gain an understanding of the organizations custom rules first we must observe the ones already created/inplace. 
In order to do so I traverse to the custom.rules file located in the /home/analyst directory

I execute the cat command to read the file and its contents

``` cat custom.rules ```

![image](https://github.com/user-attachments/assets/6bbbb075-e944-4b5e-8137-9e9f6498575c)


- Note: Suricata rules are made up of three components that must be understood in order to properly read them

*Component 1.) The Action*

![image](https://github.com/user-attachments/assets/1abca6c5-ce12-408a-b148-8873fa518809)
The action, as seen above highlighed in orange, is the first part of the signature and determines the action to take if all conditions are met

The most common actions for signatures in Suricata are  ```alert```, ```drop``` and ```reject```

The above signature contains a single ```alert``` as an action. The alert keyword instructs to alert on selected network traffic. The IDS will then inspect traffic packers and send out an alert in case it matches

The ```drop``` action creates an alert as well for the system however it drops the traffic. This action will only occur when Suricata runs in IPS mode


The ```pass``` action allows traffic to pass through the network inference. Pass rule may be used to override other rules.

*Component 2.) The Header*

![image](https://github.com/user-attachments/assets/07adcf34-d2f1-455a-926a-6b3a231f3b86)

The header, as listed above, defines the signatures network traffic. Included are attributes such as protocols, source and destination IP addresses, source and destination ports and traffic direction

The field directly after the action keyword is the protocol field, a part of the header. In the example above it is ```HTTP```

![image](https://github.com/user-attachments/assets/5cb049b9-bbdc-4187-9cfe-4ed8882991b4)


Because the protocol is HTTP we can infer that the rule is set to only apply to HTTP traffic

Within the http protocol are the parameters which reads

![image](https://github.com/user-attachments/assets/379c26bc-ec65-40b0-8d3b-75ff34685aca)

Like in TCP logs, the left side of the arrow indicates the source location and the right side indicates destination location. Above the source location is ```$HOME_NET any``` and the destination location is ```$EXTERNAL_NET any```

Note: within Suricata, the word any catches traffic from any port defined in the ```$HOME_NET``` network

*Component 3.) The Rule Options*

![image](https://github.com/user-attachments/assets/4aacb13a-ed7f-435f-a79f-5116fc81ea98)

In Suricata, the wide range of ruleoptions allows the user to customize signatures to their specific needs inside of their parameters. 


Within the signature provided we can see the following

```msg:``` is the pathway by which the alert text is provided with ```”Get on wire”``` being the text

```flow:established; to_server``` option makes it clear that packets from the source/client to the server (device receiving communication) should have matching packets.

```Content: “GET” ``` option informs Suricata to be on the lookout for the word ```GET``` in the content of the ```http.method``` Part of the packet

```sid:12345``` stands for signature ID which is an option that identifies the rule with its own specific numerical value- almost like a MAC address

```rev:3``` signifies the version of the signature. In this case this is the third version/revision

#### *Task 2: Trigger a custom rule in Suricata*

My goal here is to trigger a custom rule in Suricata and then examining the alert logs that follow

To first begin my task I have to traverse to the ```/var/log/Suricata``` folder. 

![image](https://github.com/user-attachments/assets/6517b699-60d5-43aa-8483-fcfa19fc77be)

Note: Despite the above command being accurate, Suricata has not been initialized yet- thus no files will be available to view 

To initialize Suricata I utilized the command sudo (Super user do)

![image](https://github.com/user-attachments/assets/ef4e911c-3231-471d-a65e-c0ad56e2e95f)


## Suricata Command Breakdown - Data Table

| Option                  | Description                                                                                                           |
|-------------------------|-----------------------------------------------------------------------------------------------------------------------|
| `-r sample.pcap`         | Specifies the input file to mimic network traffic. In this case, the `sample.pcap` file contains captured network packets. |
| `-S custom.rules`        | Instructs Suricata to use a specific set of rules from the `custom.rules` file for analyzing the traffic.             |
| `-k none`                | Disables checksum validation. This can be used to speed up processing by skipping the integrity checks of packet data. |


note: Checksums act as a way to detect if a packet has been modified in transit. 

Now that Suricata has been initialzed we are able to check the folder again.

![image](https://github.com/user-attachments/assets/4c86c665-c7e5-4027-8bbc-1d5c3d332a15)


From here we move to investigate the fast.log file via the command

``` cat /var/log/suricata/fast.log ```


![image](https://github.com/user-attachments/assets/c3e4cdcb-08ac-4079-b79b-ccd587eddd83)

We can see that within the fast.log file that it contains alert entries. Each line/entry in fast.log is linked to an alert generated by Suricata when it processes a packet that meets the conditions of an alert generating rule. Each line contains the same information within the alert- The rule that triggered it, the source, destination and direction of traffic 


### 3. Examin Eve.json output

Our next goal is to examine the output that Suricata generates within the eve.json file

With this file being located in the same directory as the last one we only have to execute a simple cat command followed by the files path to access it
``` cat /var/log/suricata/eve.json ```

![image](https://github.com/user-attachments/assets/98c91794-b13a-48a4-a973-713b967c94b3)


Once the command is executed, the raw contents of the file are output. 

In order to better view the information I use the ```jq``` command to display it simpler

![image](https://github.com/user-attachments/assets/b5684ecb-82bb-4246-9656-db179da96650)

When analyzing the output we can see an alert put out with a severity of 3  

![image](https://github.com/user-attachments/assets/75c0479b-409d-45db-bc92-6c926e419a5a)

While the information is good, I still wanted to extract more specific data. In order to do so I executed the following command

``` jq -c "[.timestamp,.flow_id,.alert.signature,.proto,.dest_ip]" /var/log/suricata/eve.json```

## jq Command Breakdown 

| Field/Option                     | Description                                                                                                 |
|-----------------------------------|-------------------------------------------------------------------------------------------------------------|
| `jq -c`                           | The `-c` option outputs the result in compact JSON format, which removes whitespace for easier parsing.      |
| `.timestamp`                      | Extracts the timestamp from the JSON payload, indicating when the event occurred.                            |
| `.flow_id`                        | Extracts the flow ID, which uniquely identifies a particular network flow.                                   |
| `.alert.signature` or `.msg`      | Extracts the alert signature or message, which contains the description of the detected event or alert.      |
| `.proto`                          | Extracts the protocol (e.g., TCP, UDP) used for the network communication.                                   |
| `.dest_ip`                        | Extracts the destination IP address, which indicates where the traffic was headed.                           |
| `/var/log/suricata/eve.json`      | Specifies the file path to the JSON log generated by Suricata (in this case, `eve.json`).                    |


Which provides the following output:


![image](https://github.com/user-attachments/assets/a6dc9d0b-21c8-4059-845f-b7f2929f14e5)

Now we can see more clearly details such as the destination of the last IP address listed is 142.250.1.102 or that the alert signature for the first alert entry is GET on wire which outputs in the order provided in the command however I still wanted to see specific event logs related to one of the alerts flow_id’s


To display all event logs related to a specific ``` flow_id ``` from the ```eve.json``` file I used the following command jq "select(.flow_id==X)" /var/log/suricata/eve.json where “X” is replaced with the flow_ID of a previous alert. For my example I used the first alerts flow_ID

![image](https://github.com/user-attachments/assets/32415701-ef29-4f23-9251-7f5fa306cb5a)





