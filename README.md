# Update-PSGalleryModuleAArte

This Azure Automation Runbook updates modules stored in a Azure Automation Runtime Environment from PowerShell Gallery.
This is meant to only run from an Automation account with Runtime Environment activated.

To update different runtime environments with this Runbook, either change the RTE link, or create multiple Runbooks with different names.
If doing the later, remember to update the $RunbookName parameter in the Runbook to match the new name, as this is used to dynamically find the name of the RTE the Runbook is linked to.

Make sure to create an connection asset of the type AzureServicePrincipal and call it AzureRunAsConnection.
Only need to populate TenantId and SubscriptionId with real values, the other just set NA.

NOTE:
    System-generated RTEs can not be updated as they are read only through the new api.
