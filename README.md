https://github.com/user-attachments/assets/9316cc08-838b-43ad-8750-62db06f7737c

> [!TIP]
> This SDK works seamlessly alongside the [six-iot-sdk-android](https://github.com/Simple-intelligent-X/six-iot-sdk-android).

| Tested Targets | ESP32 | ESP32-C3 | ESP32-S3 |
| ----------------- | ----- | -------- | -------- |

> [!NOTE]
> This SDK is designed to work across all ESP32 SoC variants, provided the specific chipset includes a hardware connectivity module. The target framework utilized for this SDK is **ESP-IDF v5.5.1**.

---

# Overview

A comprehensive ESP32 Chipset SDK designed for the ESP32 series (including ESP32-C3, ESP32-S3, and others). It streamlines firmware engineering by providing robust, production-ready modules:

*   **Network Provisioning:** Automates device onboarding. When a user scans the device QR code via the companion application, the hardware receives the payload and triggers the provisioning workflow natively.

*   **MQTT Connectivity:** Embedded services designed to establish, maintain, and manage secure connections to your product's central MQTT broker.

*   **Shadow Service Interaction:** Simplifies state synchronization across the platform by managing transactional topics with the backend Device Shadow Service.

*   **Log Service:** Aggregates and buffers local device logs, automatically synchronizing them to the cloud infrastructure once an active network connection is validated.

*   **OTA (Over-the-Air) Updates:** A reliable, fail-safe remote firmware upgrade mechanism to ensure field devices receive seamless patches and feature rollouts.

---

## Quick Start

By default, this SDK is pre-configured to operate natively alongside the **SiX IoT Platform** and **SiX IDaaS & IAM**.

*   **[SiX IoT Platform](https://web.iot.shuhenglianchang.com/index)** handles product lifecycles and device provisioning configurations, such as unique device credentials (private keys) and network-provisioning QR codes.

*   **[SiX IDaaS & IAM](https://web.iam.shuhenglianchang.com/index)** governs device identity authentication and access control policies across the ecosystem.

> [!TIP]
> We highly recommend reviewing the [Quick Start Documentation](https://doc.iot.shuhenglianchang.com/quick-start/quick-start) before proceeding with device integration.

---

## Integration Guide

Follow these sequential steps to integrate and execute the SDK on your hardware.

### 1. Configure the SDK Environment
Verify and adjust your SDK environment options via `menuconfig` or your configuration UI as shown below:

<p align="center">
  <img src="readme/config.png" alt="Configuration Screenshot" width="700"/>
</p>

### 2. Configure Device Identities & Credentials
Navigate to the `device_certs/` directory to input your specific device credentials, target identification schemas, and provisioning QR code metadata.

### 3. Flash Credentials to the Target Board
Follow the detailed procedures outlined in [Flash.md](Flash.md) to safely write the unique device authentication payload into its dedicated NVS/storage partition.

### 4. Run and Test the SDK in Your IDE
Connect your ESP32 development target to your workstation via USB, open your preferred IDE (such as VS Code with the ESP-IDF Extension), and flash the firmware. You can monitor the local logs via the serial terminal to verify that the network provisioning and cloud synchronization tasks initiate successfully.

> [!WARNING]
> For production deployments, you should automate the provisioning pipeline to dynamically fetch unique device credentials, generate target partition table binaries, and serialize the flashing process.

---

## Technical Support & Feedback

For technical queries, architectural discussions, or ecosystem feedback, please reach out via email:

*   **Engineering Support:** stephen.yu@six-inno.cn

---

## Dedicated IoT Platform Setup

For dedicated enterprise IoT platform deployments, infrastructure hosting, or private cloud setups, please contact our solutions team:

*   **Enterprise Service:** service@six-inno.cn
