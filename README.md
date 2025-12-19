# T27 DeathNode

## Team

| Number | Name              | User                             | E-mail                              |
| -------|-------------------|----------------------------------| ------------------------------------|
| 117363 | David Pinheiro    | <https://github.com/alarmant0>   | <mailto:david.m.pinheiro@tecnico.ulisboa.pt>   |
| 116509 | João Marques      | <https://github.com/joaorvm>     | <mailto:joaorvmarques@tecnico.ulisboa.pt>     |
| 107242 | Mehak Khosa       | <https://github.com/mehakkhosa>  | <mailto:mehakpreet.khosa@tecnico.ulisboa.pt> |

![Alice](img/alice.png) ![Bob](img/bob.png) ![Charlie](img/charlie.png)

## Contents

This repository contains documentation and source code for the *Network and Computer Security (SIRS)* project.

The [REPORT](REPORT.md) document provides a detailed overview of the key technical decisions and various components of the implemented project. It offers insights into the rationale behind these choices, the project's architecture, and the impact of these decisions on the overall functionality and performance of the system.

This document presents installation and demonstration instructions.

## Installation

To see the project in action, it is necessary to setup a virtual environment, with 2 networks and 5 machines.

The following diagram shows the networks and machines:

```
10.0.1.0/24 (Auth net)                10.0.2.0/24 (Client/Gateway net)

  [ Auth 10.0.1.20:443 ]   <------>   [ Gateway 10.0.2.10:443 ]  <------>  [ Alice ]
                                                                             [ Bob ]
                                                                             [ Kira ]
```

### Prerequisites

All the virtual machines are based on: Linux 64-bit, Java 17, keytool, Maven.

Download and install a virtual machine. Clone the base machine to create the other machines.

### Machine configurations

For each machine, there is an initialization script with the machine name, with prefix `init-` and suffix `.sh`, that installs all the necessary packages and makes all required configurations in a clean machine.

Inside each machine, use Git to obtain a copy of all the scripts and code.

```sh
git clone https://github.com/tecnico-sec/T27-DeathNode
```

Next we have custom instructions for each machine.

#### Auth Machine

This machine runs the Authentication and Invitation Token Service on port 443.

To verify:

```sh
./setup_scripts/ca-generate.sh
./setup_scripts/run-vm.sh auth
```

To test:

```sh
curl -k https://10.0.1.20:443/tokens
```

The expected results are a JSON response with available invitation tokens.

If you receive the following message `TLS=false` then ensure the CA certificates exist in `certs/ca/` and the keystore is generated.

#### Gateway Machine

This machine runs the main Application Server on port 443 and connects to Auth at `https://10.0.1.20:443`.

To verify:

```sh
./setup_scripts/run-vm.sh gateway
```

To test:

```sh
curl -k https://10.0.2.10:443/health
```

The expected results are a healthy status response.

If you receive the following message `No plugin found for prefix 'exec'` then the Maven cache is missing; follow the Offline Maven section.

#### Client Machines (Alice, Bob, Kira)

These machines run the terminal UI client and connect to Gateway at `https://10.0.2.10:443`.

To verify:

```sh
./setup_scripts/run-vm.sh alice
./setup_scripts/run-vm.sh bob
./setup_scripts/run-vm.sh kira
```

To test:

```sh
NODE_PASS=alice12 ./setup_scripts/run-vm.sh alice
```

The expected results are the terminal UI launching with TLS connection to Gateway.

If you receive the following message `Keystore password must be at least 6 characters` then set a longer `NODE_PASS`.

## Demonstration

Now that all the networks and machines are up and running, the system demonstrates invitation-token-based authorization with TLS.

```sh
# Create invitation token
curl -k -X POST https://10.0.1.20:443/tokens -d '{"description":"Demo token"}'

# Client joins with token (first-time)
./setup_scripts/run-vm.sh alice  # Enter token when prompted
```

IMPORTANT: show evidence of the security mechanisms in action; show message payloads, print relevant messages, perform simulated attacks to show the defenses in action, etc.

This concludes the demonstration.

## Additional Information

### Links to Used Tools and Libraries

- [Java 17](https://openjdk.java.net/)
- [Maven 3.9.5](https://maven.apache.org/)
- [Lanterna](https://github.com/mabe02/lanterna)
- [Gson](https://github.com/google/gson)
- [SQLite-JDBC](https://github.com/xerial/sqlite-jdbc)

### Versioning

We use [SemVer](http://semver.org/) for versioning.

### License

This project is licensed under the MIT License - see the [LICENSE.txt](LICENSE.txt) for details.

END OF README
