
#############################################################
#  ___  ___  ____  __  __  ___  _  _  ____  ____  ___       #
# / __)(__ )(  _ \(  )(  )/ __)( )/ )( ___)(_  _)/ __)      #
# \__ \ (_ \ ) _ < )(__)(( (__  )  (  )__)   )(  \__ \      #
# (___/(___/(____/(______)\___)(_)\_)(____) (__) (___/      #
#                                                           #
#############################################################
################################################################################
##                                References
###  https://docs.aws.amazon.com/programmatic-ingestion/latest/userguide/what-is-programmatic-ingestion.html
###  https://aws.amazon.com/blogs/security/how-to-compare-tenable-io-and-aws-security-finding-format-reports-for-cloud-asset-visibility/
################################################################################

# Find vulnerabilities on AWS misconfigurations
    # 1. Create a user, generate an access key and add it to this script
    #    a. Create a new user
    #       Create a new user credentials for programmatic access
    #       $ aws iam create-user --user-name <user_name>
    #       List user details
    #       $ aws iam get-user
    #    b. Assign the new policy S3_CV_SCAN to the user
    #       $ aws iam put-user-policy --user-name <user_name> --policy-name S3_CV_SCAN --policy-document file://S3_CV_SCAN.json
    #    c. Generate an access key for the user
    #       $ aws iam create-access-key --user-name <user_name>
    #       Wrap the access key with the secret. The output will be in var access_key and secret_key
    #       $ aws configure
    # 2. Set var s3_input as the S3 bucket name you want to scan

__author__ = "Felix Alcala"
__copyright__ = "Copyleft 2021, Felix Alcala"
__credits__ = ["Felix Alcala"]
__license__ = "GPL"
__version__ = "0.01a"
__maintainer__ = "dethlocker"
__email__ = "dethlocker@0xdeadbeef.ai"
__status__ = "DevSoup"

# Import AWS SDK package
import boto3

# Import Regular expressions package
import re

# Import logging package
import logging
logging.basicConfig(filename='log-file.log', level=logging.DEBUG,
                    format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
logging.getLogger('boto').setLevel(logging.CRITICAL)
logging.getLogger('boto3').setLevel(level=logging.CRITICAL)


# suppress InsecureRequestWarning for unverified HTTPS request
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Variables
s3_input = "s3-input"
access_key = 'access key'
secret_key = 'secret key'

# Load keys and initialize the AWS session
session = boto3.Session(
    aws_access_key_id=access_key,
    aws_secret_access_key=secret_key,
)

# Load the S3 buckets
s3_client = session.client(service_name='s3')

# Load the boto3 S3 resource
    # ACL check
    # Allows programmatic access to ACL operations.
s3_resource_acl = session.resource('s3')
    # Bucket policy check
    # Allows programmatic access to bucket policy operations.
s3_resource_policy = session.resource('s3')
    # Buckets check
    # Allows programmatic access to buckets operations.
s3_resource_buckets = session.resource('s3')


def acl_check(s3_resource_acl, bucket_input):
    response_acl = s3_resource_acl.BucketAcl(bucket_input).load()
    try:
        response_acl['Owner']['Name']
        print("\nS3 Bucket owner:", response_acl['Owner']['Name'])
    except KeyError:
        print("\nNo Owner")
    except TypeError:
        print("\nNo Owner")
    permission_acl = response_acl['Grants']
    count = 0
    for user in permission_acl:
        try:
            print(permission_acl[count]['Permission'], " : ", permission_acl[count]['Grantee']['URI'])
        except KeyError:
            print(permission_acl[count]['Permission'], " : ", permission_acl[count]['Grantee']['EmailAddress'])
        except AttributeError:
            print(permission_acl[count]['Permission'], " : ", permission_acl[count]['Grantee']['DisplayName'])
        except TypeError:
            print("\nNo users with ACL access on this bucket")
        count += 1
    return


def policy_check(s3_resource_policy, bucket_input):
    response_policy = s3_resource_policy.BucketPolicy(bucket_input).policy.read()
    response_policy = response_policy['Policy']
    try:
        access_permissions = re.findall(r'(?:[\*]{4}Allow[\*]{4}.*[\*]{4}S3[\*]{4})', response_policy)
        for line in access_permissions:
            print("Access permission found: ", line)
    except KeyError:
        print("No Access permission allowed")
    except urllib3.exceptions.InsecureRequestWarning:
        print("No Access permission allowed")
    except TypeError:
        print("No Access permission allowed")
    return


def buckets_check(bucket_input):
    print("\nMisconfigurations on bucket policy or ACL:")
    # Check if the bucket is a versioned bucket, it has multiple policies, one for the versions and another for the bucket
    versioned = s3_client.get_bucket_versioning(Bucket=bucket_input)
    versioned = versioned["Status"]
    if versioned == "Enabled":
        # Check if the bucket has an ACL
        acl_check(s3_resource_acl, bucket_input)
        print("\n *****************\n")
        # Check if the bucket has a policy
        policy_check(s3_resource_policy, bucket_input)
        print("\n *****************\n")
        # Check if the bucket is encrypted
        encryption = s3_client.get_bucket_encryption(Bucket=bucket_input)
        try:
            encryption = encryption['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault'][
                'SSEAlgorithm']
            if encryption == "AES256":
                print("Bucket versioned:", versioned, "\nBucket encrypted:", encryption)
            else:
                print("Bucket versioned:", versioned, "\nBucket not encrypted")
        except IndexError:
            print("Bucket versioned:", versioned, "\nBucket not encrypted")
        except TypeError:
            print("Bucket versioned:", versioned, "\nBucket not encrypted")

        # Check if the bucket has any public access
        public_access = s3_client.get_public_access_block(Bucket=bucket_input)
        print(public_access)
        try:
            # Get the list of public access
            list_public_access = public_access['PublicAccessBlockConfiguration']['BlockPublicAcls']
            perm_public_access = public_access['PublicAccessBlockConfiguration']['BlockPublicPolicy']
            write_public_access = public_access['PublicAccessBlockConfiguration']['IgnorePublicAcls']
            read_public_access = public_access['PublicAccessBlockConfiguration']['RestrictPublicBuckets']
            print("Bucket versioned:", versioned, "\nBucket encrypted:", encryption, "\nBlockPublicAcls:",
                  list_public_access, "\nBlockPublicPolicy:", perm_public_access, "\nIgnorePublicAcls:",
                  write_public_access, "\nRestrictPublicBuckets:", read_public_access)
        except urllib3.exceptions.InsecureRequestWarning:
            print("Bucket versioned:", versioned, "\nBucket encrypted:", encryption, "\nPublic access is not enabled")
        except TypeError:
            print("Bucket versioned:", versioned, "\nBucket encrypted:", encryption, "\nPublic access is not enabled")
        except KeyError:
            print("Bucket versioned:", versioned, "\nBucket encrypted:", encryption, "\nPublic access is not enabled")

    else:
        # Check if the bucket has an ACL
        acl_check(s3_resource_acl, bucket_input)
        print("\n *****************\n")
        # Check if the bucket has a policy
        policy_check(s3_resource_policy, bucket_input)
        print("\n *****************\n")
        # Check if the bucket is encrypted
        encryption = s3_client.get_bucket_encryption(Bucket=bucket_input)
        try:
            encryption = encryption['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault'][
                'SSEAlgorithm']
            if encryption == "AES256":
                print("Bucket versioned:", versioned, "\nBucket encrypted:", encryption)
            else:
                print("Bucket versioned:", versioned, "\nBucket not encrypted")
        except IndexError:
            print("Bucket versioned:", versioned, "\nBucket not encrypted")
        except TypeError:
            print("Bucket versioned:", versioned, "\nBucket not encrypted")

        # Check if the bucket has any public access
        public_access = s3_client.get_public_access_block(Bucket=bucket_input)
        print(public_access)
        try:
            # Get the list of public access
            list_public_access = public_access['PublicAccessBlockConfiguration']['BlockPublicAcls']
            perm_public_access = public_access['PublicAccessBlockConfiguration']['BlockPublicPolicy']
            write_public_access = public_access['PublicAccessBlockConfiguration']['IgnorePublicAcls']
            read_public_access = public_access['PublicAccessBlockConfiguration']['RestrictPublicBuckets']
            print("Bucket versioned:", versioned, "\nBucket encrypted:", encryption, "\nBlockPublicAcls:",
                  list_public_access, "\nBlockPublicPolicy:", perm_public_access, "\nIgnorePublicAcls:",
                  write_public_access, "\nRestrictPublicBuckets:", read_public_access)
        except urllib3.exceptions.InsecureRequestWarning:
            print("Bucket versioned:", versioned, "\nBucket encrypted:", encryption, "\nPublic access is not enabled")
        except TypeError:
            print("Bucket versioned:", versioned, "\nBucket encrypted:", encryption, "\nPublic access is not enabled")
        except KeyError:
            print("Bucket versioned:", versioned, "\nBucket encrypted:", encryption, "\nPublic access is not enabled")


# Get a list of all the buckets
all_buckets = s3_resource_buckets.buckets.all()

for bucket_input in all_buckets:
    # Print out each bucket name
    print("Checking bucket: ", bucket_input.name)
    # Print out the bucket name and status
    buckets_check(bucket_input.name)

# Print the date and time
print(time.strftime("\n   %A, %Y/%m/%d, %H:%M:%S"))
