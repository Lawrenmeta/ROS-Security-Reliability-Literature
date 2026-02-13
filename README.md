# ROS-Security-Reliability-Literature
A curated list of 87 key papers on ROS/ROS 2 security vulnerabilities, reliability faults, and mitigation strategies (2014-2025).



> A curated list of **87 key scientific publications** covering the trustworthiness landscape of the Robot Operating System (ROS 1 & ROS 2).
> 

This repository is organized based on a **Systematic Literature Review (2014-2025)**. It categorizes system defects into two primary dimensions: **Software Vulnerabilities** (Security) and **Software Reliability Faults** (Safety).

## 📖 Table of Contents

- [Master Literature Index (S1-S87)](https://www.notion.so/30541cf8b15a8076b866f14fd48316cd?pvs=21)
- [Software Security](https://www.notion.so/30541cf8b15a8076b866f14fd48316cd?pvs=21)
    - [Vulnerability & Attack Analysis](https://www.notion.so/30541cf8b15a8076b866f14fd48316cd?pvs=21)
    - [Offensive Tools & Reconnaissance](https://www.notion.so/30541cf8b15a8076b866f14fd48316cd?pvs=21)
    - [Hardening: Application Layer](https://www.notion.so/30541cf8b15a8076b866f14fd48316cd?pvs=21)
    - [Hardening: Communication Layer](https://www.notion.so/30541cf8b15a8076b866f14fd48316cd?pvs=21)
    - [Runtime Monitoring & IDS](https://www.notion.so/30541cf8b15a8076b866f14fd48316cd?pvs=21)
- [Software Reliability](https://www.notion.so/30541cf8b15a8076b866f14fd48316cd?pvs=21)
    - [Fault Studies & Dependencies](https://www.notion.so/30541cf8b15a8076b866f14fd48316cd?pvs=21)
    - [Static Analysis](https://www.notion.so/30541cf8b15a8076b866f14fd48316cd?pvs=21)
    - [Dynamic Analysis (Fuzzing)](https://www.notion.so/30541cf8b15a8076b866f14fd48316cd?pvs=21)
    - [Formal Verification](https://www.notion.so/30541cf8b15a8076b866f14fd48316cd?pvs=21)
    - [Semantic & Self-Adaptive Faults](https://www.notion.so/30541cf8b15a8076b866f14fd48316cd?pvs=21)
- [Contributing](https://www.notion.so/30541cf8b15a8076b866f14fd48316cd?pvs=21)
- [License](https://www.notion.so/30541cf8b15a8076b866f14fd48316cd?pvs=21)

---

## 📚 Master Literature Index

| ID | Year | Title | Source | Category | Topic |
| --- | --- | --- | --- | --- | --- |
| **S1** | 2022 | ROS network security for a swing doors automation in a robotized hospital | SIBCON | Security | Vulnerability Analysis |
| **S2** | 2017 | A study on ROS vulnerabilities and countermeasure | HRI Companion | Security | Vulnerability Analysis |
| **S3** | 2017 | The role of security in human-robot shared environments: A case study in ROS-based surveillance robots | RO-MAN | Security | Vulnerability Analysis |
| **S4** | 2019 | Smart malware that uses leaked control data of robotic applications: the case of Raven-II surgical robots | RAID | Security | Malware / Attack Analysis |
| **S5** | 2019 | ROSploit: Cybersecurity tool for ROS | IRC | Security | Pentesting Tool |
| **S6** | 2019 | Scanning the internet for ROS: A view of security in robotics research | ICRA | Security | Network Scanning |
| **S7** | 2020 | Security on ROS: analyzing and exploiting vulnerabilities of ROS-based systems | LARS/SBR | Security | Vulnerability Analysis |
| **S8** | 2020 | Security controller synthesis for ROS-based robot | QRS-C | Security | Control Synthesis |
| **S9** | 2020 | Penetration testing ROS | Book Chapter | Security | Pentesting |
| **S10** | 2021 | Novel denial-of-service attacks against cloud-based multi-robot systems | Info. Sciences | Security | DoS Attack Analysis |
| **S11** | 2021 | Data tampering attack design for ROS-based object detection and tracking robotic platform | ICCAIS | Security | Data Tampering |
| **S12** | 2022 | Analysis of attacks on robotic operation system | CEUR Workshop | Security | Attack Analysis |
| **S13** | 2022 | Cyberattacks on self-driving cars and surgical and eldercare robots | SCN | Security | Vulnerability Analysis |
| **S14** | 2023 | An analysis of DoS attack on robot operating system | GUJS | Security | DoS Attack Analysis |
| **S15** | 2024 | Understanding the Internet-Wide Vulnerability Landscape for ROS-based Robotic Vehicles | Preprint | Security | Network Scanning |
| **S16** | 2025 | Analyzing impact and systemwide effects of the SlowROS attack in an industrial automation scenario | Future Internet | Security | DoS Attack (SlowROS) |
| **S17** | 2018 | Analyzing cyber-physical threats on robotic platforms | Sensors | Security | Cyber-Physical Threats |
| **S18** | 2019 | Network reconnaissance and vulnerability excavation of secure DDS systems | EuroS&PW | Security | ROS 2 Reconnaissance |
| **S19** | 2022 | On the (in)security of Secure ROS2 | CCS | Security | ROS 2 Encryption/Policy |
| **S20** | 2025 | Investigating security threats in multi-tenant ROS 2 systems | ICRA | Security | ROS 2 Access Control |
| **S21** | 2020 | AVGuardian: Detecting and mitigating publish-subscribe overprivilege for autonomous vehicle systems | EuroS&P | Security | ROS 2 Over-privilege |
| **S22** | 2019 | Credential masquerading and OpenSSL spy: Exploring ROS 2 using DDS security | arXiv | Security | Supply Chain/Credential |
| **S23** | 2024 | Defending against APT attacks in robots: A multi-phase game-theoretical approach | GameSec | Security | ROS 2 Traffic Flooding |
| **S24** | 2023 | Analyzing security vulnerability and forensic investigation of ROS2: A case study | ICRAI | Security | ROS 2 Resource Isolation |
| **S25** | 2018 | Robotics CTF (RCTF), a playground for robot hacking | arXiv | Security | CTF / Education |
| **S26** | 2022 | An experience report on challenges in learning the Robot Operating System | RoSE | Reliability | Dev Challenges |
| **S27** | 2023 | Getting started with ROS2 development: A case study of software development challenges | RoSE | Reliability | Dev Challenges |
| **S28** | 2020 | The forgotten case of the dependency bugs: On the example of the Robot Operating System | ICSE-SEIP | Reliability | Dependency Faults |
| **S29** | 2019 | Can I depend on you? Mapping the dependency and quality landscape of ROS packages | IRC | Reliability | Build Faults |
| **S30** | 2022 | ROSDiscover: Statically detecting run-time architecture misconfigurations in robotics systems | ICSA | Reliability | Arch. Misconfiguration |
| **S31** | 2016 | A framework for quality assessment of ROS repositories | IROS | Reliability | Quality Assessment |
| **S32** | 2022 | Probabilistic inference of simulation parameters via parallel differentiable simulation | ICRA | Reliability | Semantic Faults |
| **S33** | 2021 | PhysFrame: type checking physical frames of reference for robotic systems | ESEC/FSE | Reliability | Coordinate Frame Errors |
| **S34** | 2017 | Dimensional inconsistencies in code and ROS messages: A study of 5.9m lines of code | IROS | Reliability | Unit Mismatches |
| **S35** | 2020 | Learning camera miscalibration detection | ICRA | Reliability | Semantic Faults |
| **S36** | 2022 | Control parameters considered harmful: Detecting range specification bugs in drone configuration modules via learning-guided search | ICSE | Reliability | Configuration Bugs |
| **S37** | 2025 | An evaluation of self-adaptive mechanisms for misconfigurations in small uncrewed aerial systems | TAAS | Reliability | Misconfig Mitigation |
| **S38** | 2016 | Cybersecurity in autonomous systems: Evaluating the performance of hardening ROS | Preprint | Security | App-Layer Hardening |
| **S39** | 2018 | Cybersecurity in autonomous systems: hardening ROS using encrypted communications and semantic rules | ROBOT | Security | App-Layer Hardening |
| **S40** | 2016 | Increasing ROS 1.x communication security for medical surgery robot | SMC | Security | App-Layer Hardening |
| **S41** | 2016 | Application-level security for ROS-based applications | IROS | Security | App-Layer Hardening |
| **S42** | 2019 | Policy-based access control for robotic applications | SOSE | Security | Access Control (PBAC) |
| **S43** | 2018 | Cross-layer secure and resilient control of delay-sensitive networked robot operating systems | CCTA | Security | Resilient Control |
| **S44** | 2021 | Designing a security platform for collaborating autonomous systems - an experience report | ICSA-C | Security | App-Layer Hardening |
| **S45** | 2014 | Message authentication codes for secure remote non-native client connections to ROS enabled robots | TePRA | Security | Remote Authentication |
| **S46** | 2021 | A cryptography-powered infrastructure to ensure the integrity of robot workflows | JCP | Security | Workflow Integrity |
| **S47** | 2022 | AuthROS: Secure data sharing among robot operating systems based on Ethereum | QRS | Security | Data Provenance |
| **S48** | 2023 | Proposed technique for data security with the AES algorithm in Robot Operating System (ROS) | ICSEC | Security | Data Encryption |
| **S49** | 2016 | SROS: Securing ROS over the wire, in the graph, and through the kernel | arXiv | Security | Comm-Layer Hardening |
| **S50** | 2019 | Enhancing security in ROS | ACSS | Security | OS-Level Isolation |
| **S51** | 2019 | Runtime verification on hierarchical properties of ROS-based robot swarms | Trans. Rel. | Security | Lightweight Security |
| **S52** | 2018 | CryptoROS: A secure communication architecture for ROS-based applications | IJACSA | Security | Proxy-based Encryption |
| **S53** | 2019 | A novel solution for securing robot communications based on the MQTT protocol and ROS | SII | Security | Protocol Bridging |
| **S54** | 2020 | TROS: Protecting humanoids ROS from privileged attackers | IJSR | Security | TEE (SGX) |
| **S55** | 2022 | SROS2: Usable cyber security tools for ROS 2 | IROS | Security | Comm-Layer Hardening |
| **S56** | 2025 | ROSEc: Intra-process isolation for ROS composition with memory protection keys | TASE | Security | Intra-process Isolation |
| **S57** | 2024 | Support remote attestation for decentralized robot operating system (ROS) using trusted execution environment | ICBC | Security | Remote Attestation |
| **S58** | 2023 | Quantifying DDS-Cerberus network control overhead | Supercomp | Security | Key Distribution |
| **S59** | 2024 | Decentralized information-flow control for ROS2 | NDSS | Security | Info Flow Control |
| **S60** | 2024 | Automating ROS2 security policies extraction through static analysis | IROS | Security | Policy Automation |
| **S61** | 2018 | Security and performance considerations in ROS 2: A balancing act | arXiv | Security | Performance Analysis |
| **S62** | 2022 | Analyzing interoperability and security overhead of ROS2 DDS middleware | MED | Security | Performance Analysis |
| **S63** | 2024 | Performance evaluation of a prototype UAV-based secure communication system employing ROS and chaotic communications | ICUAS | Security | Lightweight Encryption |
| **S64** | 2018 | Quantitative analysis of security in distributed robotic frameworks | RAS | Security | Performance Analysis |
| **S65** | 2014 | ROSRV: Runtime verification for robots | RV | Security | Runtime Monitoring |
| **S66** | 2020 | ROSMonitoring: a runtime verification framework for ROS | TAROS | Security | Runtime Monitoring |
| **S67** | 2019 | ROS-Defender: SDN-based security policy enforcement for robotic applications | SPW | Security | SDN-based Defense |
| **S68** | 2024 | Implementing a Robot Intrusion Prevention System (RIPS) for ROS 2 | arXiv | Security | Intrusion Prevention |
| **S69** | 2025 | Watch your callback: Offline anomaly detection using machine learning in ROS 2 | IEEE Access | Security | Anomaly Detection |
| **S70** | 2020 | Intrusion detection on robot cameras using spatio-temporal autoencoders: A self-driving car application | VTC | Security | Intrusion Detection |
| **S71** | 2022 | Detecting data injection attacks in ROS systems using machine learning | LARS | Security | Intrusion Detection |
| **S72** | 2023 | Trusted operations of a military ground robot in the face of man-in-the-middle cyberattacks using deep learning convolutional neural networks: Real-time experimental outcomes | TDSC | Security | Intrusion Detection |
| **S73** | 2025 | DCWM-LSTM: A novel attack detection framework for robotic arms | IEEE Access | Security | Intrusion Detection |
| **S74** | 2014 | Increasing ROS reliability and safety through advanced introspection capabilities | Informatik | Security | System Introspection |
| **S75** | 2015 | Drums: A middleware-aware distributed robot monitoring system | Middleware | Security | Distributed Monitoring |
| **S76** | 2024 | ROS-Lighthouse: An Intrusion Detection System (IDS) in ROS Using Ensemble Learning | WPMC | Security | Intrusion Detection |
| **S77** | 2022 | ROZZ: Property-based fuzzing for robotic programs in ROS | ICRA | Reliability | Fuzzing |
| **S78** | 2024 | Multi-dimensional and message-guided fuzzing for robotic programs in Robot Operating System | ASPLOS | Reliability | Fuzzing |
| **S79** | 2020 | ROS2-fuzz: automatic fuzzing for ROS2 | GitHub | Reliability | Fuzzing |
| **S80** | 2022 | RoboFuzz: fuzzing robotic systems over Robot Operating System (ROS) for finding correctness bugs | ESEC/FSE | Reliability | Fuzzing |
| **S81** | 2023 | Toward the trustworthiness of industrial robotics using differential fuzz testing | TII | Reliability | Fuzzing |
| **S82** | 2023 | DiscoFuzzer: discontinuity-based vulnerability detector for robotic systems | Authorea | Reliability | Fuzzing |
| **S83** | 2024 | Enhancing ROS system fuzzing through callback tracing | ISSTA | Reliability | Fuzzing |
| **S84** | 2018 | Checking consistency of robot software architectures in ROS | RoSE | Reliability | Static Analysis |
| **S85** | 2024 | ROSInfer: Statically inferring behavioral component models for ROS-based robotics systems | ICSE | Reliability | Static Analysis |
| **S86** | 2025 | ROSCallBaX: Statically detecting inconsistencies in callback function setup of robotic systems | PACM | Reliability | Static Analysis |
| **S87** | 2017 | Formal verification of ROS-based robotic applications using timed-automata | FormaliSE | Reliability | Formal Verification |

---

## 🛡️ Software Security

### Vulnerability & Attack Analysis

*Focus: ROS 1/ROS 2 design flaws, specific attacks (MITM, DoS, Injection), and impact analysis.*

- [S20] **[2025] Investigating security threats in multi-tenant ROS 2 systems** (ICRA) `[ROS 2]` `[Access Control]`
- [S16] **[2025] Analyzing impact and systemwide effects of the SlowROS attack in an industrial automation scenario** (Future Internet) `[DoS]`
- [S23] **[2024] Defending against APT attacks in robots: A multi-phase game-theoretical approach** (GameSec) `[ROS 2]`
- [S14] **[2023] An analysis of DoS attack on robot operating system** (GUJS) `[DoS]`
- [S24] **[2023] Analyzing security vulnerability and forensic investigation of ROS2: A case study** (ICRAI) `[ROS 2]` `[Isolation]`
- [S19] **[2022] On the (in)security of Secure ROS2** (CCS) `[Encryption]` `[ROS 2]`
- [S12] **[2022] Analysis of attacks on robotic operation system** (CEUR Workshop) `[Attack Analysis]`
- [S13] **[2022] Cyberattacks on self-driving cars and surgical and eldercare robots** (SCN) `[Flooding]`
- [S1] **[2022] ROS network security for a swing doors automation in a robotized hospital** (SIBCON) `[Snooping]`
- [S10] **[2021] Novel denial-of-service attacks against cloud-based multi-robot systems** (Information Sciences) `[DoS]`
- [S11] **[2021] Data tampering attack design for ROS-based object detection and tracking robotic platform** (ICCAIS) `[Tampering]`
- [S7] **[2020] Security on ROS: analyzing and exploiting vulnerabilities of ROS-based systems** (LARS/SBR) `[MITM]`
- [S21] **[2020] AVGuardian: Detecting and mitigating publish-subscribe overprivilege for autonomous vehicle systems** (EuroS&P) `[Over-privilege]`
- [S4] **[2019] Smart malware that uses leaked control data of robotic applications: the case of Raven-II surgical robots** (RAID) `[Malware]`
- [S18] **[2019] Network reconnaissance and vulnerability excavation of secure DDS systems** (EuroS&PW) `[ROS 2]`
- [S22] **[2019] Credential masquerading and OpenSSL spy: Exploring ROS 2 using DDS security** (arXiv) `[Supply Chain]`
- [S17] **[2018] Analyzing cyber-physical threats on robotic platforms** (Sensors) `[Cyber-Physical]`
- [S2] **[2017] A study on ROS vulnerabilities and countermeasure** (HRI Companion) `[Hijacking]`
- [S3] **[2017] The role of security in human-robot shared environments: A case study in ROS-based surveillance robots** (RO-MAN) `[Injection]`

### Offensive Tools & Reconnaissance

*Focus: Pentesting tools, network scanners, and CTF platforms.*

- [S15] **[2024] Understanding the Internet-Wide Vulnerability Landscape for ROS-based Robotic Vehicles** (Preprint) `[Scanning]`
- [S8] **[2020] Security controller synthesis for ROS-based robot** (QRS-C) `[Synthesis]`
- [S9] **[2020] Penetration testing ROS** (Book Chapter) `[Pentesting]`
- [S5] **[2019] ROSploit: Cybersecurity tool for ROS** (IRC) `[Tool]`
- [S6] **[2019] Scanning the internet for ROS: A view of security in robotics research** (ICRA) `[Scanning]`
- [S25] **[2018] Robotics CTF (RCTF), a playground for robot hacking** (arXiv) `[CTF]`

### Hardening: Application Layer

*Focus: Encryption nodes, authentication wrappers, and blockchain integration.*

- [S48] **[2023] Proposed technique for data security with the AES algorithm in Robot Operating System (ROS)** (ICSEC) `[AES]`
- [S47] **[2022] AuthROS: Secure data sharing among robot operating systems based on Ethereum** (QRS) `[Blockchain]`
- [S44] **[2021] Designing a security platform for collaborating autonomous systems - an experience report** (ICSA-C) `[OAuth/TLS]`
- [S46] **[2021] A cryptography-powered infrastructure to ensure the integrity of robot workflows** (JCP) `[Integrity]`
- [S42] **[2019] Policy-based access control for robotic applications** (SOSE) `[PBAC]`
- [S39] **[2018] Cybersecurity in autonomous systems: hardening ROS using encrypted communications and semantic rules** (ROBOT) `[Encryption]`
- [S43] **[2018] Cross-layer secure and resilient control of delay-sensitive networked robot operating systems** (CCTA) `[Resilient]`
- [S38] **[????] Cybersecurity in autonomous systems: Evaluating the performance of hardening ROS** (Preprint) `[Performance]`
- [S40] **[2016] Increasing ROS 1.x communication security for medical surgery robot** (SMC) `[Auth]`
- [S41] **[2016] Application-level security for ROS-based applications** (IROS) `[Auth]`
- [S45] **[2014] Message authentication codes for secure remote non-native client connections to ROS enabled robots** (TePRA) `[Remote Auth]`

### Hardening: Communication Layer

*Focus: SROS, DDS-Security, TEEs, and OS-level isolation.*

- [S56] **[2025] ROSEc: Intra-process isolation for ROS composition with memory protection keys** (TASE) `[Isolation]`
- [S57] **[2024] Support remote attestation for decentralized robot operating system (ROS) using trusted execution environment** (ICBC) `[Attestation]`
- [S59] **[2024] Decentralized information-flow control for ROS2** (NDSS) `[DIFC]`
- [S60] **[2024] Automating ROS2 security policies extraction through static analysis** (IROS) `[Policy]`
- [S63] **[2024] Performance evaluation of a prototype UAV-based secure communication system employing ROS and chaotic communications** (ICUAS) `[Encryption]`
- [S58] **[2023] Quantifying DDS-Cerberus network control overhead** (Supercomputing) `[Kerberos]`
- [S55] **[2022] SROS2: Usable cyber security tools for ROS 2** (IROS) `[SROS2]`
- [S62] **[2022] Analyzing interoperability and security overhead of ROS2 DDS middleware** (MED) `[DDS]`
- [S54] **[2020] TROS: Protecting humanoids ROS from privileged attackers** (IJSR) `[SGX]`
- [S50] **[2019] Enhancing security in ROS** (ACSS) `[AppArmor]`
- [S51] **[2019] Runtime verification on hierarchical properties of ROS-based robot swarms** (Trans. Rel.) `[HMAC]`
- [S53] **[2019] A novel solution for securing robot communications based on the MQTT protocol and ROS** (SII) `[MQTT]`
- [S52] **[2018] CryptoROS: A secure communication architecture for ROS-based applications** (IJACSA) `[Proxy]`
- [S61] **[2018] Security and performance considerations in ROS 2: A balancing act** (arXiv) `[Performance]`
- [S64] **[2018] Quantitative analysis of security in distributed robotic frameworks** (RAS) `[Analysis]`
- [S49] **[2016] SROS: Securing ROS over the wire, in the graph, and through the kernel** (arXiv) `[SROS]`

### Runtime Monitoring & Intrusion Detection

*Focus: Anomaly detection, ML/DL-based IDS, and SDN defenses.*

- [S69] **[2025] Watch your callback: Offline anomaly detection using machine learning in ROS 2** (IEEE Access) `[ML]`
- [S73] **[2025] DCWM-LSTM: A novel attack detection framework for robotic arms** (IEEE Access) `[LSTM]`
- [S68] **[2024] Implementing a Robot Intrusion Prevention System (RIPS) for ROS 2** (arXiv) `[IPS]`
- [S76] **[2024] ROS-Lighthouse: An Intrusion Detection System (IDS) in ROS Using Ensemble Learning** (WPMC) `[Ensemble]`
- [S72] **[2023] Trusted operations of a military ground robot in the face of man-in-the-middle cyberattacks using deep learning convolutional neural networks: Real-time experimental outcomes** (TDSC) `[CNN]`
- [S71] **[2022] Detecting data injection attacks in ROS systems using machine learning** (LARS) `[ML]`
- [S66] **[2020] ROSMonitoring: a runtime verification framework for ROS** (TAROS) `[Runtime Verif]`
- [S70] **[2020] Intrusion detection on robot cameras using spatio-temporal autoencoders: A self-driving car application** (VTC) `[Video IDS]`
- [S67] **[2019] ROS-Defender: SDN-based security policy enforcement for robotic applications** (SPW) `[SDN]`
- [S75] **[2015] Drums: A middleware-aware distributed robot monitoring system** (Middleware) `[Monitoring]`
- [S65] **[2014] ROSRV: Runtime verification for robots** (RV) `[Runtime Verif]`
- [S74] **[2014] Increasing ROS reliability and safety through advanced introspection capabilities** (Informatik) `[Introspection]`

---

## ⚙️ Software Reliability

### Fault Studies & Dependencies

*Focus: Empirical studies on development challenges, dependencies, and build systems.*

- [S27] **[2023] Getting started with ROS2 development: A case study of software development challenges** (RoSE) `[ROS 2]`
- [S26] **[2022] An experience report on challenges in learning the Robot Operating System** (RoSE) `[Challenges]`
- [S28] **[2020] The forgotten case of the dependency bugs: On the example of the Robot Operating System** (ICSE-SEIP) `[Dependency]`
- [S29] **[2019] Can I depend on you? Mapping the dependency and quality landscape of ROS packages** (IRC) `[Build]`

### Static Analysis

*Focus: Checking architecture, physical units, and coordinate frames without execution.*

- [S86] **[2025] ROSCallBaX: Statically detecting inconsistencies in callback function setup of robotic systems** (PACM) `[Callbacks]`
- [S85] **[2024] ROSInfer: Statically inferring behavioral component models for ROS-based robotics systems** (ICSE) `[Behavior]`
- [S30] **[2022] ROSDiscover: Statically detecting run-time architecture misconfigurations in robotics systems** (ICSA) `[Architecture]`
- [S32] **[2022] Probabilistic inference of simulation parameters via parallel differentiable simulation** (ICRA) `[Simulation]`
- [S33] **[2021] PhysFrame: type checking physical frames of reference for robotic systems** (ESEC/FSE) `[Frames]`
- [S84] **[2018] Checking consistency of robot software architectures in ROS** (RoSE) `[Architecture]`
- [S34] **[2017] Dimensional inconsistencies in code and ROS messages: A study of 5.9m lines of code** (IROS) `[Units]`
- [S31] **[2016] A framework for quality assessment of ROS repositories** (IROS) `[Quality]`

### Dynamic Analysis (Fuzzing)

*Focus: Property-based fuzzing, message mutation, and simulation-based testing.*

- [S78] **[2024] Multi-dimensional and message-guided fuzzing for robotic programs in Robot Operating System** (ASPLOS) `[Rofer]`
- [S83] **[2024] Enhancing ROS system fuzzing through callback tracing** (ISSTA) `[Tracing]`
- [S81] **[2023] Toward the trustworthiness of industrial robotics using differential fuzz testing** (TII) `[Differential]`
- [S82] **[2023] DiscoFuzzer: discontinuity-based vulnerability detector for robotic systems** (Authorea) `[Discontinuity]`
- [S77] **[2022] ROZZ: Property-based fuzzing for robotic programs in ROS** (ICRA) `[Fuzzing]`
- [S80] **[2022] RoboFuzz: fuzzing robotic systems over Robot Operating System (ROS) for finding correctness bugs** (ESEC/FSE) `[Semantic]`
- [S79] **[2020] ROS2-fuzz: automatic fuzzing for ROS2** (GitHub) `[Mutation]`

### Formal Verification

*Focus: Model checking, timed automata, and Petri nets.*

- [S87] **[2017] Formal verification of ROS-based robotic applications using timed-automata** (FormaliSE) `[Timing]`

### Semantic & Self-Adaptive Faults

*Focus: Miscalibration, parameter range bugs, and self-repair.*

- [S37] **[2025] An evaluation of self-adaptive mechanisms for misconfigurations in small uncrewed aerial systems** (TAAS) `[Self-Adaptive]`
- [S36] **[2022] Control parameters considered harmful: Detecting range specification bugs in drone configuration modules via learning-guided search** (ICSE) `[Config]`
- [S35] **[2020] Learning camera miscalibration detection** (ICRA) `[Calibration]`

---

## 🤝 Contributing

Contributions are welcome! Please format new entries as: `[ID] **[Year] Title** - Source`.

## 📄 License

This repository is licensed under the MIT License.
