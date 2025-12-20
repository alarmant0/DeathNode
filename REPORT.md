# CXX DeathNode / ChainOfProduct / CivicEcho Project Report

## 1. Introduction

DeathNode is an anonymous reporting platform used by a peer-based network run by a group called The Cult of Kika. The system allows members to submit reports about alleged crimes or suspects before this information reaches the authorities. Because the reports can include sensitive information, protecting the identity of users was a major concern from the start. For this reason, users do not use real names and instead interact with the system using pseudonyms.

Each user runs their own node, which stores reports locally in encrypted form. These reports are shared with other nodes through periodic synchronization. Using a peer-to-peer approach makes the system more resilient, but it also creates some problems. Nodes cannot simply trust each other, so they must be able to detect if a report was changed, deleted, duplicated, or received in the wrong order.

To prevent these issues, reports are protected using cryptographic mechanisms. Encryption ensures that only authorized nodes can read the content, and integrity checks allow nodes to detect any changes. Although the system was originally fully decentralized, an extra requirement was later added to control who can join the network. For that reason, a central authorization server was introduced to approve new participants and issue time-limited credentials, while still keeping users anonymous.

## 2. Project Development

### 2.1. Secure Document Format

#### 2.1.1. Design

(_Outline the design of your custom cryptographic library and the rationale behind your design choices, focusing on how it addresses the specific needs of your chosen business scenario._)

(_Include a complete example of your data format, with the designed protections._)

#### 2.1.2. Implementation

(_Detail the implementation process, including the programming language and cryptographic libraries used._)

(_Include challenges faced and how they were overcome._)

### 2.2. Infrastructure

#### 2.2.1. Network and Machine Setup

(_Provide a brief description of the built infrastructure._)

(_Justify the choice of technologies for each server._)

#### 2.2.2. Server Communication Security

(_Discuss how server communications were secured, including the secure channel solutions implemented and any challenges encountered._)

(_Explain what keys exist at the start and how are they distributed?_)

### 2.3. Security Challenge

#### 2.3.1. Challenge Overview

(_Describe the new requirements introduced in the security challenge and how they impacted your original design._)

#### 2.3.2. Attacker Model

(_Define who is fully trusted, partially trusted, or untrusted._)

(_Define how powerful the attacker is, with capabilities and limitations, i.e., what can he do and what he cannot do_)

#### 2.3.3. Solution Design and Implementation

(_Explain how your team redesigned and extended the solution to meet the security challenge, including key distribution and other security measures._)

(_Identify communication entities and the messages they exchange with a UML sequence or collaboration diagram._)  

## 3. Conclusion

In this project, we designed DeathNode, an anonymous peer-based reporting system that allows users to share crime related information without revealing their identity. The main focus was making sure reports could be stored and shared securely between nodes, even though the system does not fully trust its participants.

All the security requirements were met. Reports are encrypted so only authorized nodes can read them, and integrity checks make it possible to detect any changes. During synchronization, nodes can also detect missing, duplicated, or out-of-order reports. Adding a central authorization server helped control who can join the network, while still keeping users anonymous.

There are still some things that could be improved, like handling expired or compromised credentials more smoothly or making synchronization work better on bigger networks. Overall, this project helped us see how anonymity and security can be combined in a distributed system and gave us practical experience dealing with real-world design challenges.

## 4. Bibliography

Segurança em redes informáticas: André Zúquete 2018 5ª edição, FCA. ISBN: 9789727228577
Network Security Essentials: Applications and Standards,: William Stallings 2017 6th Edition, Pearson. ISBN: 978-0134527338
Security Engineering: A Guide to Building Dependable Distributed Systems: Ross Anderson 2020 3rd Edition, ISBN: 978-1-119-64281-7

----
END OF REPORT
