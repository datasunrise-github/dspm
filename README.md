---
title: How to Deploy DataSunrise DSPM: Step-by-Step Setup
description: 
published: 1
date: 2025-09-16T15:27:26.010Z
editor: markdown
dateCreated: 2025-09-16T14:32:58.462Z
---


# How to Deploy DataSunrise DSPM: Step-by-Step Setup



## What is DataSunrise DSPM?

**[DataSunrise Data Security Posture Management (DSPM)](https://www.datasunrise.com/knowledge-center/dspm-data-security-posture-management/)** is a platform for comprehensive **data protection in AWS**. It automatically discovers databases and storages, deploys DataSunrise instances, and applies security rules.

DSPM creates DataSunrise instances that can operate in three modes:

* **Sensitive Data Discovery** — automatic discovery and classification of sensitive data.
* **Proxy Mode** — filtering, data masking, and access control for databases.
* **Audit Trailing Mode** — auditing and logging user activities using native DBMS and cloud services.


<figure>
  <img src="https://www.datasunrise.com/wp-content/uploads/2025/09/how-to-deploy-datasunrise-dspm-step-by-step-setup-01-diagram-illustrating-aws-services-including-redshi.webp" alt="How to Deploy DataSunrise DSPM: Step-by-Step Setup - Diagram illustrating AWS services including Redshift and DynamoDB integration." class="alignnone size-full" />
</figure>


## Step-by-Step Installation of DataSunrise DSPM

### 1. Download and Preparation

1. Download Terraform scripts for DSPM from GitHub: [Terraform files for DSPM](https://github.com/datasunrise-github/dspm/tree/main/aws).
2. Navigate to the scripts directory:

   ```bash
   cd path/to/dspm-terraform
   ```
3. Copy the parameter file and rename it:

   ```bash
   cp parameters.auto.tfvars.json.exm parameters.auto.tfvars.json
   ```
4. Edit `parameters.auto.tfvars.json` — set AWS region, S3 bucket name, and networking parameters.

### 2. Initialization

```bash
terraform init
```

### 3. Planning

```bash
terraform plan --out ./metadata/main.tfplan
```

### 4. Apply

```bash
terraform apply ./metadata/main.tfplan
```

### 5. First Login

1. Open the DSPM web console from the Terraform output.
2. Select provider **AWS** and authenticate.

<figure>
  <img src="https://www.datasunrise.com/wp-content/uploads/2025/09/how-to-deploy-datasunrise-dspm-step-by-step-setup-02-ui-showing-options-for-selecting-a-datasunrise-ins.webp" alt="How to Deploy DataSunrise DSPM: Step-by-Step Setup - UI showing options for selecting a DataSunrise instance and configuring database user details." class="alignnone size-full" />
  <figcaption class="default-figcaptions">DataSunrise Posture Management Interface.</figcaption>
</figure>

## Supported Assets

| **Databases on EC2/VM** | **AWS**                    | **Azure**                                              |
| ----------------------- | -------------------------- | ------------------------------------------------------ |
| MySQL                   | Elasticsearch / OpenSearch | Cosmos DB (Cassandra, NoSQL, Mongo, Postgres, Account) |
| PostgreSQL              | Redshift                   | PostgreSQL flexible servers                            |
| Greenplum               | Athena                     | MySQL flexible servers                                 |
| Impala                  | DocumentDB                 | SQL Server                                             |
| SAP HANA                | S3                         | Storage Accounts                                       |
| Teradata                | EFS                        |                                                        |
| SQL Server              | FSx                        |                                                        |
| Apache Hive             | Aurora (MySQL, PostgreSQL) |                                                        |
| Sybase                  | Oracle                     |                                                        |
| Vertica                 | SQL Server                 |                                                        |
| Informix                | MariaDB                    |                                                        |
| Oracle                  | MySQL                      |                                                        |
| CockroachDB             | PostgreSQL                 |                                                        |
| MariaDB                 | DynamoDB                   |                                                        |
| Cassandra               |                            |                                                        |
| Netezza                 |                            |                                                        |
| MongoDB                 |                            |                                                        |
| DynamoDB                |                            |                                                        |


## Main Capabilities

* **[Sensitive Data Discovery](https://www.datasunrise.com/data-discovery/)** — automatic detection and classification of sensitive data in the cloud infrastructure.
* **[Data Masking](https://www.datasunrise.com/professional-info/what-is-data-masking/)** and access control — enforce masking, encryption, and user-level rules.
* **[Audit Trails](https://www.datasunrise.com/knowledge-center/audit-trails)** — logging of user and system activities, with advanced data audit.
* **[High Availability](https://www.datasunrise.com/datasunrise-quick-start-on-aws/)** — ensures uninterrupted operation with clustering and failover support.
* **[Integration with AWS Secrets Manager](https://www.datasunrise.com/professional-info/running-ds-on-kubernetes/)** — provides secure storage and automated rotation of credentials.


## Business Benefits

* Minimized risk of leaks and unauthorized access.
* Centralized management of data security in AWS.
* Compliance with GDPR, HIPAA, PCI DSS, and other standards.
* Fast integration into existing infrastructure.
* Scalability for companies of any size.


## Conclusion

**DataSunrise DSPM** is a universal tool for database security in AWS. It automates asset discovery and protection, simplifies data audit, and helps organizations stay compliant with security standards.

If you want to reliably protect data in AWS and simplify administration, **DSPM** is your best choice.

[ds_cta]
