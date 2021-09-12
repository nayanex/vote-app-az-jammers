"""
Azure Automation documentation : https://aka.ms/azure-automation-python-documentation
Azure Python SDK documentation : https://aka.ms/azure-python-sdk
"""

import threading
import getopt
import sys
import azure.mgmt.resource
import azure.mgmt.storage
#import azure.mgmt.compute
import automationassets
import OpenSSL
from msrestazure import azure_active_directory
import adal

import azure.mgmt.compute.v2019_12_01.operations.VirtualMachineScaleSetVMsOperations

resource_group = "acdnd-c4-project"
vmss_name = "udacity-vmss"

# Returns a credential based on an Azure Automation RunAs connection dictionary
def get_automation_runas_credential(runas_connection):
    """Returs a credential that can be used to authenticate against Azure resources"""
    # Get the Azure Automation RunAs service principal certificate
    cert = automationassets.get_automation_certificate("AzureRunAsCertificate")
    sp_cert = OpenSSL.crypto.load_pkcs12(cert)
    pem_pkey = OpenSSL.crypto.dump_privatekey(
        OpenSSL.crypto.FILETYPE_PEM, sp_cert.get_privatekey()
    )

    # Get run as connection information for the Azure Automation service principal
    application_id = runas_connection["ApplicationId"]
    thumbprint = runas_connection["CertificateThumbprint"]
    tenant_id = runas_connection["TenantId"]

    # Authenticate with service principal certificate
    resource = "https://management.core.windows.net/"
    authority_url = "https://login.microsoftonline.com/" + tenant_id
    context = adal.AuthenticationContext(authority_url)
    return azure_active_directory.AdalAuthentication(
        lambda: context.acquire_token_with_client_certificate(
            resource, application_id, pem_pkey, thumbprint
        )
    )

# Authenticate to Azure using the Azure Automation RunAs service principal
automation_runas_connection = automationassets.get_automation_connection(
    "AzureRunAsConnection"
)

azure_credential = get_automation_runas_credential(automation_runas_connection)
subscription_id = str(automation_runas_connection["SubscriptionId"])

compute_client = azure.mgmt.compute.ComputeManagementClient(
    azure_credential, subscription_id
)


def stop_vmss(resource_group, vmss_name):
    """Stops a vm in the specified resource group"""
    # Stop the VMSS
    print(dir(compute_client.virtual_machine_scale_set_vms))
    #print(type(compute_client.virtual_machine_scale_set_vms))
    vmss_stop = compute_client.virtual_machine_scale_set_vms.begin_deallocate(
        resource_group, vmss_name
    )
    vmss_stop.wait()

def run():
        print(
            "Stopping " + vmss_name + " in resource group " + resource_group
        )
        sys.stdout.flush()
        stop_vmss(resource_group, vmss_name)
        print("Stopped " + vmss_name + " in resource group " + resource_group)
        sys.stdout.flush()

#run()

if __name__ == "__main__":
    run() 