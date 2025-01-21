import xml.etree.ElementTree as ET
from azure.identity import ClientSecretCredential
from azure.keyvault.secrets import SecretClient
import os

# Step 1: Parse the XML file to get the Vault Name
def get_vault_name_from_xml(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()
    key_vault_config = root.find("azureKeyVault")
    if key_vault_config is None or key_vault_config.find("vaultName") is None:
        raise Exception("Vault name not found in the XML file.")
    return key_vault_config.find("vaultName").text

# Step 2: Retrieve secrets from Azure Key Vault
def get_secret_from_key_vault(vault_name, secret_name):
    credential = ClientSecretCredential(
        client_id=os.environ["AZURE_CLIENT_ID"],
        tenant_id=os.environ["AZURE_TENANT_ID"],
        client_secret=os.environ["AZURE_CLIENT_SECRET"],
    )
    vault_url = f"https://{vault_name}.vault.azure.net"
    client = SecretClient(vault_url=vault_url, credential=credential)
    return client.get_secret(secret_name).value

# Main execution
if __name__ == "__main__":
    # Path to the XML file
    config_file_path = "config.xml"  # Adjust the path if necessary
    secret_name = "example-secret"  # Replace with your secret's name

    try:
        # Step 1: Get the Vault Name from the XML file
        vault_name = get_vault_name_from_xml(config_file_path)
        print(f"Vault Name: {vault_name}")

        # Step 2: Retrieve the secret
        secret_value = get_secret_from_key_vault(vault_name, secret_name)
        print(f"Secret Value: {secret_value}")
    except Exception as e:
        print(f"Error: {e}")
