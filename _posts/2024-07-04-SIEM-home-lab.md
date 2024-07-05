---
title: SIEM Home Lab with Elastic
categories: [Blue Team]
tags: [elastic, siem, project]
author: Jenil
image: assets/images/SIEM-homelab/elastic-siem.png
---

In this project, I have set up a home lab for Elastic Stack Security Information and Event Management (SIEM) using the Elastic Web portal and a Kali Linux VM. I also generated security events on the Kali VM, set up an agent to forward data to the SIEM, and query and analyze the logs in the SIEM.

## Overview of the steps
- Set up a free Elastic account.
- Install the Kali VM.
- Configure the Elastic Agent on the Linux VM to collect the logs and forward it to the SIEM.
- Generate security events on the Kali VM.
- Query to find the security events in the Elastic SIEM.
- Create a Dashboard to visualize security events.
- Create alerts for security events.

### Step 1: Set up a free Elastic account
Let's first create a free Elastic account by following the below steps:
1. Sign up for a free trial to use Elastic Cloud at [https://cloud.elastic.co/registration](https://cloud.elastic.co/registration)
2. Start  a free trial.
3. Create an Elastic deployment, choose the region and deployment size.
![Deployment](/assets/images/SIEM-homelab/deployment.png)

### Step 2: Set up Kali Linux VM
1. Download the Kali Linux VM from the official website.
2. Load the Kali VM file in preferred platform, such as VirtualBox and VMware.
3. Follow the steps on-screen.
4. Once installed successfully, log in with username and password as "kali".

### Step 3: Configure the Elastic agent
An agent is a software program that is installed on a device, such as a server or endpoint, to collect and send data to a centralized system for analysis and monitoring. In the context of Elastic SIEM, an agent is used to collect and forward security-related events from your endpoints to your Elastic SIEM instance.
Let's set up the agent on our Kali VM by following the below steps:
1. Click top left menu bar and then click "Add integrations".
![Add integration](/assets/images/SIEM-homelab/add_integrations.png){: width="400"}

2. Search for “Elastic Defend”, install it and follow the steps to get script.
![Elastic defend](/assets/images/SIEM-homelab/Search_elastic_defend.png)
![Script for elastic agent](/assets/images/SIEM-homelab/Script_for_elastic_agent.png)
3. Paste this script in command line on Kali VM. Once installed, check it by using command: `sudo systemctl status elastic-agent.service`
![Check installation](/assets/images/SIEM-homelab/check_installation.png)

### Step 4: Generate Security Events on Kali VM
Now, we will create some events on our Kali VM so that it can reflect on our Elastic portal.
1. We will use cmd tool called Nmap that is mainly used for port scanning.
2. Run few nmap scans on Kali VM.
![Nmap scan1](/assets/images/SIEM-homelab/nmap_scan_1.png)
![Nmap scan2](/assets/images/SIEM-homelab/nmap_scan_2.png)

### Step 5: Query to Find the Security Events in the Elastic SIEM
Now that we have generated few security events, we can start querying and analyzing the logs.
1. Click on the top left menu bar and click on "Logs" under "Observability" section.
![](/assets/images/SIEM-homelab/logs_tab.png)

2. There are too many logs, to filter those logs related to our nmap scan, we can write this query in search field: process.args: "nmap"
![](/assets/images/SIEM-homelab/nmap_log_entries.png)
3. We can see one log entry and can see any particular log. In this log, we can see which command we have used.
![](/assets/images/SIEM-homelab/nmap_log_one_entry.png)
This is crucial because by generating and analyzing different types of security events in Elastic SIEM like the one above, or generating authentication failures by typing in the wrong password for a user or attempting SSH logins an incorrect password, we can gain a better understanding of how security incidents are detected, investigated, and responded to in real-world environments.

### Step 6: Create a Dashboard to visualize security events
We can also use the visualizations and dashboards in the Elastic SIEM to analyze the logs and identify patterns or anomalies in the data. For example, we can create a simple dashboard that shows a count of security events over time.

Follow the steps to do that:
1. Click on the top left menu bar and click on the "Dashboards" under "Analytics" section.
![](/assets/images/SIEM-homelab/dashboard_tab.png){: .center}

2. Now, click "Create dashboard" and then "Create Visualization" to add new visualization in the dashboard.
3. We can choose the visualization type, such as "Area", "Line", "Bar", etc.
![Data visualization](/assets/images/SIEM-homelab/data_visualization.png)
4. Now, we can select what data we want to show on horizontal and vertical axes.

### Step 7: Create alerts for security events
In a SIEM, alerts are a crucial feature for detecting security incidents and responding to them in a timely manner. Alerts are created based on predefined rules or custom queries, and can be configured to trigger specific actions when certain conditions are met. In this task, we will walk through the steps of creating an alert in the Elastic SIEM instance to detect Nmap scans and use of "sudo" command by regular user.

By following these steps, you can create an alert that will monitor your logs for Nmap scan events and then notify you when they are detected:
1. Click on the top left menu bar and click "Alerts" under "Security" section.
![](/assets/images/SIEM-homelab/alerts_tab.png){: width="400" .center}

2. Now, click on "Manage rules" and then click "Create new rule".
3. Under "Define rule" section, select "Custom query" option.
4. Under "Custom query", set the condition for the rule. Write process.args: "nmap" to detect nmap scan events.
![Custom nmap query](/assets/images/SIEM-homelab/custom_nmap_query.png)
5. In "About rule" section, write name and description of the rule and set the severity of the alert according to the importance.
![](/assets/images/SIEM-homelab/about_rule.png)
6. In the “Actions” section, select the action you want to take when the rule is triggered. You can choose to send an email notification, create a Slack message, or trigger a custom webhook.
7. Finally, click the “Create and enable rule” button to create the alert.
8. We can see rule overview by selecting particular rule in "Manage rules" section.
![Nmap rule overview](/assets/images/SIEM-homelab/rule_overview.png)
9. This rule will monitor our logs for Nmap scan events. If an Nmap scan event is detected, the alert will be triggered and the selected action will be taken. We can view and manage your alerts on the “Alerts” section under “Security.”
![Nmap successful detection](/assets/images/SIEM-homelab/successful_alert.png)

Now, we will create one more rule to detect the use of "sudo" command by normal user.
1. We will follow above step and use this custom query for the desired detection: process.args: "sudo" and user.name: "kali". And we will set the severity to critical as this is crucial alert.
![Sudo rule overview](/assets/images/SIEM-homelab/sudo_rule_overview.png)
2. In below image we can see we were successfully able to detect the use of "sudo" command by "kali" user.
![Sudo successful detection](/assets/images/SIEM-homelab/sudo_rule_result.png)


## Conclusion
In this project, we have set up a home lab using Elastic SIEM and a Kali VM. We forwarded data from the Kali VM to the SIEM using the Elastic agent, generated security events on the Kali VM using Nmap, and queried and analyzed the logs in the SIEM using the Elastic web interface. We also created a dashboard to visualize security events and then created an alert to detect security events.

This home lab provided a valuable environment for learning and practicing the skills necessary for effective security monitoring and incident response using Elastic SIEM. By following these steps, I got hands-on experience with using a SIEM and improved my security monitoring skills.

Reference: [A Simple Elastic SIEM Lab](https://medium.com/@aali23/a-simple-elastic-siem-lab-6765159ee2b2)

Thank you for reading.